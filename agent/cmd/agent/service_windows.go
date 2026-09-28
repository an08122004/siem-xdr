//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// Windows Service viết thẳng trên advapi32 (không thêm dependency ngoài), cùng cách
// golang.org/x/sys/windows/svc làm: StartServiceCtrlDispatcher -> ServiceMain -> báo trạng thái,
// nhận lệnh Stop/Shutdown qua handler rồi hủy context của agent.

var (
	advapi32                          = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
)

const (
	svcWin32OwnProcess  = 0x10
	svcStopped          = 1
	svcStartPending     = 2
	svcStopPending      = 3
	svcRunning          = 4
	svcAcceptStop       = 0x1
	svcAcceptShutdown   = 0x4
	ctrlStop            = 1
	ctrlShutdown        = 5
	errServiceSpecific  = 1066 // ERROR_SERVICE_SPECIFIC_ERROR
	errNotUnderSCM      = 1063 // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
	errServiceNotExists = 1060
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceTableEntry struct {
	name *uint16
	proc uintptr
}

var svc struct {
	handle   uintptr
	run      func(context.Context) error
	stopOnce sync.Once
	stop     chan struct{}
	err      error
}

func setStatus(state, accepts, exitCode uint32) {
	st := serviceStatus{ServiceType: svcWin32OwnProcess, CurrentState: state, ControlsAccepted: accepts}
	if exitCode != 0 {
		st.Win32ExitCode, st.ServiceSpecificExitCode = errServiceSpecific, exitCode
	}
	if state == svcStartPending || state == svcStopPending {
		st.WaitHint = uint32(stopTimeout.Milliseconds()) + 5000
	}
	procSetServiceStatus.Call(svc.handle, uintptr(unsafe.Pointer(&st)))
}

func ctrlHandler(ctrl, _, _, _ uintptr) uintptr {
	switch uint32(ctrl) {
	case ctrlStop, ctrlShutdown:
		setStatus(svcStopPending, 0, 0)
		svc.stopOnce.Do(func() { close(svc.stop) })
	}
	return 0
}

func serviceMain(argc uint32, argv **uint16) uintptr {
	name, _ := syscall.UTF16PtrFromString(serviceName)
	h, _, err := procRegisterServiceCtrlHandlerExW.Call(uintptr(unsafe.Pointer(name)), syscall.NewCallback(ctrlHandler), 0)
	if h == 0 {
		svc.err = fmt.Errorf("RegisterServiceCtrlHandlerEx: %w", err)
		return 0
	}
	svc.handle = h
	setStatus(svcStartPending, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-svc.stop; cancel() }()
	setStatus(svcRunning, svcAcceptStop|svcAcceptShutdown, 0)
	svc.err = svc.run(ctx)
	cancel()
	exit := uint32(0)
	if svc.err != nil {
		log.Printf("agent dừng với lỗi: %v", svc.err)
		exit = 1
	}
	setStatus(svcStopped, 0, exit)
	return 0
}

// runAsService trả về khi SCM dừng service. Gọi ngoài SCM (chạy tay với -service) thì báo lỗi ngay.
func runAsService(run func(context.Context) error) error {
	svc.run, svc.stop = run, make(chan struct{})
	name, _ := syscall.UTF16PtrFromString(serviceName)
	table := []serviceTableEntry{{name: name, proc: syscall.NewCallback(serviceMain)}, {}}
	r, _, err := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == errNotUnderSCM {
			return errors.New("-service chỉ dùng khi được Windows Service Control Manager khởi động; chạy tay thì bỏ -service")
		}
		return fmt.Errorf("StartServiceCtrlDispatcher: %w", err)
	}
	return svc.err
}

func sc(args ...string) ([]byte, error) {
	return exec.Command("sc.exe", args...).CombinedOutput()
}

func installService(configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if out, err := sc(scCreateArgs(exe, configPath)...); err != nil {
		return fmt.Errorf("sc create (cần mở PowerShell bằng Administrator): %v %s", err, out)
	}
	if out, err := sc(scFailureArgs()...); err != nil {
		return fmt.Errorf("sc failure: %v %s", err, out)
	}
	_, _ = sc("description", serviceName, "SIEM/XDR agent: thu log, FIM, phản ứng (siem-xdr)")
	if out, err := sc("start", serviceName); err != nil {
		return fmt.Errorf("sc start: %v %s", err, out)
	}
	return nil
}

func uninstallService() error {
	_, _ = sc("stop", serviceName)
	out, err := sc("delete", serviceName)
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == errServiceNotExists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sc delete (cần Administrator): %v %s", err, out)
	}
	return nil
}

// hardenStateDir: bỏ quyền thừa kế từ C:\ProgramData (mặc định Users được đọc), chỉ để
// SYSTEM, Administrators và tài khoản đang chạy agent. Thư mục chứa token và log an ninh.
func hardenStateDir(dir string) error {
	args := []string{dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"}
	if sid, err := currentUserSID(); err == nil {
		args = append(args, "*"+sid+":(OI)(CI)F")
	}
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v %s", err, out)
	}
	return nil
}

func currentUserSID() (string, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}

// warnConfigPerms: trên Windows nên đặt file cấu hình trong thư mục trạng thái (đã được siết quyền).
func warnConfigPerms(path string) {
	log.Printf("lưu ý: file cấu hình %s chứa enrollment_key — nên đặt trong thư mục trạng thái (chỉ SYSTEM/Administrators đọc được)", path)
}
