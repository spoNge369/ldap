// +build !windows

package ldap

import (
	"errors"
)

// NTLMChallengeBind performs the NTLMSSP bind operation defined in the given request
func (l *Conn) NTLMSSPIChallengeBind(ntlmBindRequest *NTLMSSPIBindRequest) (*NTLMBindResult, error) {
	return nil, errors.New("sspi auth is not supported on this platform, please try something else")
}
