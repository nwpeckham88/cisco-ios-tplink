package tplink

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func (c *Client) GetSystemInfo() (SystemInfo, error) {
	html, err := c.page("SystemInfoRpm")
	if err != nil {
		return SystemInfo{}, err
	}
	ds := asMap(extractVar(html, "info_ds"))
	if len(ds) == 0 {
		return SystemInfo{}, fmt.Errorf("could not parse SystemInfoRpm.htm")
	}
	return SystemInfo{
		Description: asString(oneAt(getListValue(ds, "descriStr"), 0)),
		MAC:         asString(oneAt(getListValue(ds, "macStr"), 0)),
		IP:          asString(oneAt(getListValue(ds, "ipStr"), 0)),
		Netmask:     asString(oneAt(getListValue(ds, "netmaskStr"), 0)),
		Gateway:     asString(oneAt(getListValue(ds, "gatewayStr"), 0)),
		Firmware:    asString(oneAt(getListValue(ds, "firmwareStr"), 0)),
		Hardware:    asString(oneAt(getListValue(ds, "hardwareStr"), 0)),
	}, nil
}

func (c *Client) SetDeviceDescription(description string) error {
	params := url.Values{}
	params.Set("sysName", description)
	_, err := c.cfgGet("system_name_set.cgi", params)
	return err
}

func (c *Client) GetIPSettings() (IPSettings, error) {
	html, err := c.page("IpSettingRpm")
	if err != nil {
		return IPSettings{}, err
	}
	ds := asMap(extractVar(html, "ip_ds"))
	if len(ds) == 0 {
		return IPSettings{}, fmt.Errorf("could not parse IpSettingRpm.htm")
	}
	return IPSettings{
		DHCP:    asBool(ds["state"]),
		IP:      asString(oneAt(getListValue(ds, "ipStr"), 0)),
		Netmask: asString(oneAt(getListValue(ds, "netmaskStr"), 0)),
		Gateway: asString(oneAt(getListValue(ds, "gatewayStr"), 0)),
	}, nil
}

func (c *Client) SetIPSettings(ip, netmask, gateway string, dhcp *bool) error {
	current, err := c.GetIPSettings()
	if err != nil {
		return err
	}
	finalDHCP := current.DHCP
	if dhcp != nil {
		finalDHCP = *dhcp
	}
	finalIP := current.IP
	if ip != "" {
		finalIP = ip
	}
	finalNetmask := current.Netmask
	if netmask != "" {
		finalNetmask = netmask
	}
	finalGateway := current.Gateway
	if gateway != "" {
		finalGateway = gateway
	}

	if !finalDHCP {
		if err := validateIPv4(finalIP, "ip"); err != nil {
			return err
		}
		if err := validateNetmask(finalNetmask); err != nil {
			return err
		}
		if err := validateIPv4(finalGateway, "gateway"); err != nil {
			return err
		}
	}

	params := url.Values{}
	if finalDHCP {
		params.Set("dhcpSetting", "1")
	} else {
		params.Set("dhcpSetting", "0")
	}
	params.Set("ip_address", finalIP)
	params.Set("ip_netmask", finalNetmask)
	params.Set("ip_gateway", finalGateway)
	_, err = c.cfgGet("ip_setting.cgi", params)
	return err
}

func (c *Client) GetLED() (bool, error) {
	html, err := c.page("TurnOnLEDRpm")
	if err != nil {
		return false, err
	}
	return asBool(extractVar(html, "led")), nil
}

func (c *Client) SetLED(on bool) error {
	params := url.Values{}
	if on {
		params.Set("rd_led", "1")
	} else {
		params.Set("rd_led", "0")
	}
	params.Set("led_cfg", "Apply")
	_, err := c.cfgGet("led_on_set.cgi", params)
	return err
}

func (c *Client) ChangePassword(oldPassword, newPassword, username string) error {
	if err := validateSecret(oldPassword, "old_password"); err != nil {
		return err
	}
	if err := validateSecret(newPassword, "new_password"); err != nil {
		return err
	}
	if username == "" {
		username = c.Username
	}
	params := url.Values{}
	params.Set("txt_username", username)
	params.Set("txt_oldpwd", oldPassword)
	params.Set("txt_userpwd", newPassword)
	params.Set("txt_confirmpwd", newPassword)
	_, err := c.cfgGet("usr_account_set.cgi", params)
	return err
}

func (c *Client) Reboot() error {
	params := url.Values{}
	params.Set("reboot_op", "1")
	_, err := c.cfgGet("reboot.cgi", params)
	c.loggedIn = false
	return err
}

func (c *Client) FactoryReset() error {
	params := url.Values{}
	params.Set("reset_op", "1")
	_, err := c.cfgGet("reset.cgi", params)
	c.loggedIn = false
	return err
}

func (c *Client) BackupConfig() ([]byte, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	return c.rawRequest(http.MethodGet, "config_back.cgi", nil, nil, "")
}

func (c *Client) RestoreConfig(configData []byte) error {
	if err := c.ensureSession(); err != nil {
		return err
	}
	body, contentType, err := restoreMultipartBody(configData)
	if err != nil {
		return fmt.Errorf("build restore payload: %w", err)
	}
	resp, err := c.rawRequest(http.MethodPost, "conf_restore.cgi", nil, body, contentType)
	if err != nil {
		return err
	}
	_ = resp
	return nil
}

func oneAt(list []any, idx int) any {
	if idx < 0 || idx >= len(list) {
		return nil
	}
	return list[idx]
}

func readAll(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	return io.ReadAll(rc)
}
