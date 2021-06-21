package ldap

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/alexbrainman/sspi/ntlm"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// NTLMChallengeBind performs the NTLMSSP bind operation defined in the given request
func (l *Conn) NTLMSSPIChallengeBind(ntlmBindRequest *NTLMSSPIBindRequest) (*NTLMBindResult, error) {
	creds, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}

	defer creds.Release()

	// generate an NTLMSSP Negotiation message for the  specified domain (it can be blank)
	cc, negMessage, err := ntlm.NewClientContext(creds)
	if err != nil {
		return nil, fmt.Errorf("err creating negmessage: %s", err)
	}
	defer cc.Release()

	// Save this for the response
	ntlmBindRequest.msg = negMessage

	msgCtx, err := l.doRequest(ntlmBindRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)
	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}
	result := &NTLMBindResult{
		Controls: make([]Control, 0),
	}
	var ntlmsspChallenge []byte

	// now find the NTLM Response Message
	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 3 {
			child := packet.Children[1].Children[1]
			ntlmsspChallenge = child.ByteValue
			// Check to make sure we got the right message. It will always start with NTLMSSP
			if len(ntlmsspChallenge) < 7 || !bytes.Equal(ntlmsspChallenge[:7], []byte("NTLMSSP")) {
				return result, GetLDAPError(packet)
			}
			l.Debug.Printf("%d: found ntlmssp challenge", msgCtx.id)
		}
	}
	if ntlmsspChallenge != nil {
		var err error
		var responseMessage []byte
		// generate a response message to the challenge with the given Username/Password if password is provided
		responseMessage, err = cc.Update(ntlmsspChallenge)
		if err != nil {
			return result, fmt.Errorf("parsing ntlm-challenge: %s", err)
		}
		packet = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

		request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

		// append the challenge response message as a TagEmbeddedPDV BER value
		auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, responseMessage, "authentication")

		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = l.sendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %s", err)
		}
		defer l.finishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %s", err)
		}
	}

	err = GetLDAPError(packet)
	return result, err
}
