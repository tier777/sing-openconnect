package openconnect

import (
	"net/url"
	"testing"
)

func TestFortinetSMSChallengeThemes(t *testing.T) {
	for _, username := range []string{
		`<input name="username" type="hidden" value="test-user">`,
		`<input name="username" type="text" style="display:none" value="test-user">`,
		`<input name="username" style="color:red; DISPLAY : none !important;" value="test-user">`,
		`<input name="username" hidden value="test-user">`,
		``,
	} {
		for _, kind := range []string{"password", "text", "number", "tel"} {
			for _, codeName := range []string{"credential", "code"} {
				html := `<form method="POST" action="/remote/logincheck">` + username + `<input type="` + kind + `" name="` + codeName + `"><input name="magic" type="hidden" value="opaque&amp;value"></form>`
				form, err := parseFortinetHTMLChallenge([]byte(html), "test-user")
				if err != nil {
					t.Fatal(err)
				}
				response := &authenticationResponse{Values: map[string]string{}}
				for _, field := range form.fields {
					response.Values[field.submissionKey] = field.value
					if field.name == codeName {
						if field.kind != AuthFormFieldPassword {
							t.Fatal("OTP must be secret")
						}
						response.Values[field.submissionKey] = "012345"
						if field.value != "" {
							t.Fatal("OTP was prefilled")
						}
					}
				}
				encoded, _, err := encodeFortinetAuthenticationResponse(form, response, "", false)
				if err != nil {
					t.Fatal(err)
				}
				values, _ := url.ParseQuery(encoded)
				if values.Get("username") != "test-user" || values.Get(codeName) != "012345" || values.Get("magic") != "opaque&value" {
					t.Fatalf("incorrect continuation: %s", encoded)
				}
			}
		}
	}
}

func TestFortinetMalformedChallengeRejected(t *testing.T) {
	for _, html := range []string{
		`<form method="GET"><input name="credential" type="password"></form>`,
		`<form method="POST"><input name="magic" type="hidden"></form>`,
		`<form method="POST"><input name="credential" type="hidden"></form>`,
		`<form method="POST"><input name="username" type="text"><input name="credential" type="password"></form>`,
	} {
		if _, err := parseFortinetHTMLChallenge([]byte(html), "test-user"); err == nil {
			t.Fatalf("accepted invalid challenge: %s", html)
		}
	}
	if _, err := parseFortinetHTMLChallenge([]byte(`<form method="POST"><input name="code" type="text"></form>`)); err == nil {
		t.Fatal("invented an unknown username")
	}
}
