package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider creates a new LDAP provider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"ldap_host": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_HOST", nil),
				Description: "The LDAP server to connect to.",
			},
			"ldap_port": {
				Type:        schema.TypeInt,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_PORT", 389),
				Description: "The LDAP protocol port (default: 389).",
			},
			"use_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_USE_TLS", true),
				Description: "Use TLS to secure the connection (default: true).",
			},
			"bind_user": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_USER", nil),
				Description: "Bind user to be used for authenticating on the LDAP server.",
			},
			"bind_password": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_PASSWORD", nil),
				Description: "Password to authenticate the Bind user.",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"ldap_object": resourceLDAPObject(),
		},

		DataSourcesMap: map[string]*schema.Resource{
			"ldap_object": dataLDAPObject(),
		},

		ConfigureFunc: configureProvider,
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		LDAPHost:     d.Get("ldap_host").(string),
		LDAPPort:     d.Get("ldap_port").(int),
		UseTLS:       d.Get("use_tls").(bool),
		BindUser:     d.Get("bind_user").(string),
		BindPassword: d.Get("bind_password").(string),
	}

	connection, err := config.initiateAndBind()
	if err != nil {
		return nil, err
	}

	return connection, nil
}
