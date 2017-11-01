package windows

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	SID_WIL_UNTRUSTED   = `S-1-16-0`
	SID_WIL_LOW         = `S-1-16-4096`
	SID_WIL_MEDIUM      = `S-1-16-8192`
	SID_WIL_MEDIUM_PLUS = `S-1-16-8448`
	SID_WIL_HIGH        = `S-1-16-12288`
	SID_WIL_SYSTEM      = `S-1-16-16384`
	SID_WIL_PROTECTED   = `S-1-16-20480`
	SID_WIL_SECURE      = `S-1-16-28672`
)

func sidToWindowsIntegrityLevel(sid *syscall.SID) (string, error) {
	sidstr, err := sid.String()
	if err != nil {
		return "", err
	}

	switch sidstr {
	case SID_WIL_UNTRUSTED:
		return "untrusted", nil
	case SID_WIL_LOW:
		return "low", nil
	case SID_WIL_MEDIUM:
		return "medium", nil
	case SID_WIL_MEDIUM_PLUS:
		return "medium_plus", nil
	case SID_WIL_HIGH:
		return "high", nil
	case SID_WIL_SYSTEM:
		return "system", nil
	case SID_WIL_PROTECTED:
		return "protected", nil
	case SID_WIL_SECURE:
		return "secure", nil
	}

	return "", errors.New("Unknown integrity level. SID: " + sidstr)
}

func GetProcessIntegrityLevel() (string, error) {
	procToken, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(syscall.Handle(procToken))

	var needed uint32

	err = syscall.GetTokenInformation(procToken, syscall.TokenIntegrityLevel, nil, 0, &needed)
	if err == nil {
		return "", errors.New("GetTokenInformation(TokenIntegrityLevel): buffer size not returned")
	}

	if err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}

	buf := make([]byte, needed)

	err = syscall.GetTokenInformation(procToken,
		syscall.TokenIntegrityLevel, &buf[0], needed,
		&needed)
	if err != nil {
		return "", err
	}

	tml := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&buf[0]))

	sid := (*syscall.SID)(unsafe.Pointer(tml.Label.Sid))

	return sidToWindowsIntegrityLevel(sid)
}

func GetIntegrityLevelToken(wns string) (syscall.Handle, error) {
	var token syscall.Handle
	var procToken syscall.Token

	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}

	err = syscall.OpenProcessToken(proc,
		syscall.TOKEN_DUPLICATE|
			syscall.TOKEN_ADJUST_DEFAULT|
			syscall.TOKEN_QUERY|
			syscall.TOKEN_ASSIGN_PRIMARY,
		&procToken)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(syscall.Handle(procToken))

	err = DuplicateTokenEx(syscall.Handle(procToken), 0, nil, SecurityImpersonation,
		TokenPrimary, &token)
	if err != nil {
		return 0, err
	}

	tml, err := tokenLabelBuild(wns)
	if err != nil {
		syscall.CloseHandle(token)
		return 0, err
	}

	err = SetTokenInformation(token,
		syscall.TokenIntegrityLevel,
		uintptr(unsafe.Pointer(tml)),
		tml.Size())
	if err != nil {
		syscall.CloseHandle(token)
		return 0, err
	}
	return token, nil
}

func tokenLabelBuild(wns string) (*TOKEN_MANDATORY_LABEL, error) {
	sid, err := syscall.StringToSid(wns)
	if err != nil {
		return nil, err
	}

	rv := &TOKEN_MANDATORY_LABEL{}
	rv.Label.Attributes = SE_GROUP_INTEGRITY
	rv.Label.Sid = sid
	return rv, nil
}
