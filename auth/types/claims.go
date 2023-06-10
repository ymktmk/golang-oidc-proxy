package types

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v3/jwt"
)

type Claims struct {
	jwt.Claims
	Groups            []string               `json:"groups,omitempty"`
	Email             string                 `json:"email,omitempty"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Name              string                 `json:"name,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	RawClaim          map[string]interface{} `json:"-"`
}

type UserInfo struct {
	Groups []string `json:"groups"`
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var httpClient HttpClient

func init() {
	httpClient = &http.Client{}
}

func (c *Claims) GetCustomGroup(customKeyName string) ([]string, error) {
	groups, ok := c.RawClaim[customKeyName]
	if !ok {
		return nil, fmt.Errorf("No claim found for key: %v", customKeyName)
	}

	sliceInterface, ok := groups.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Expected an array, got %v", groups)
	}

	newSlice := []string{}
	for _, a := range sliceInterface {
		val, ok := a.(string)
		if !ok {
			return nil, fmt.Errorf("Group name %v was not a string", a)
		}
		newSlice = append(newSlice, val)
	}

	return newSlice, nil
}

func (c *Claims) GetUserInfoGroups(accessToken, issuer, userInfoPath string) ([]string, error) {
	url := fmt.Sprintf("%s%s", issuer, userInfoPath)
	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	bearer := fmt.Sprintf("Bearer %s", accessToken)
	request.Header.Set("Authorization", bearer)

	response, err := httpClient.Do(request)

	if err != nil {
		return nil, err
	}

	userInfo := UserInfo{}

	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&userInfo)

	if err != nil {
		return nil, err
	}

	return userInfo.Groups, nil
}
