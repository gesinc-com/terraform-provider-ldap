package main

import (
	"bytes"
	"log"
	"strconv"
	"time"

	"fmt"
	"strings"

	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/r3labs/diff"
	"gopkg.in/ldap.v2"
)

const delim = ";"

var objectSchema = map[string]*schema.Schema{
	"dn": {
		Type:        schema.TypeString,
		Description: "The Distinguished Name (DN) of the object, as the concatenation of its RDN (unique among siblings) and its parent's DN.",
		Required:    true,
		ForceNew:    true,
	},
	"object_classes": {
		Type:        schema.TypeSet,
		Description: "The set of classes this object conforms to (e.g. organizationalUnit, inetOrgPerson).",
		Elem:        &schema.Schema{Type: schema.TypeString},
		Set:         schema.HashString,
		Required:    true,
	},
	"attributes": {
		Type:        schema.TypeMap,
		Description: "The map of attributes of this object; each attribute can be multi-valued.",
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
	},
}

func dataLDAPObject() *schema.Resource {
	return &schema.Resource{
		Read: resourceLDAPObjectFind,
		Schema: map[string]*schema.Schema{
			"base_dn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"objects": {
				Type:       schema.TypeList,
				Computed:   true,
				ForceNew:   true,
				ConfigMode: schema.SchemaConfigModeAttr,
				Elem: &schema.Resource{
					Schema: objectSchema,
				},
			},
		},
	}
}

func resourceLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: resourceLDAPObjectCreate,
		Read:   resourceLDAPObjectRead,
		Update: resourceLDAPObjectUpdate,
		Delete: resourceLDAPObjectDelete,
		Exists: resourceLDAPObjectExists,

		Importer: &schema.ResourceImporter{
			State: resourceLDAPObjectImport,
		},

		Schema: objectSchema,
	}
}

func resourceLDAPObjectImport(d *schema.ResourceData, meta interface{}) (imported []*schema.ResourceData, err error) {
	d.Set("dn", d.Id())
	err = readLDAPObjectImpl(d, meta, false)
	if path := os.Getenv("TF_LDAP_IMPORTER_PATH"); path != "" {
		log.Printf("[DEBUG] ldap_object::import - dumping imported object to %q", path)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// the export file does not exist
			if file, err := os.Create(path); err == nil {
				defer file.Close()
				id := d.Id()
				tokens := strings.Split(id, ",")
				if len(tokens) > 0 {
					tokens = strings.Split(tokens[0], "=")
					if len(tokens) >= 1 {
						id = tokens[1]
						//resource "ldap_object" "a123456" {
						file.WriteString(fmt.Sprintf("resource \"ldap_object\" %q {\n", id))
						//	dn = "uid=a123456,dc=example,dc=com"
						file.WriteString(fmt.Sprintf("  dn = %q\n", d.Id()))
						//  object_classes = ["inetOrgPerson", "posixAccount"]
						classes := []string{}
						for _, class := range d.Get("object_classes").(*schema.Set).List() {
							//classes[i] = fmt.Sprintf("\"%s\"", class)
							classes = append(classes, fmt.Sprintf("%q", class))
						}
						file.WriteString(fmt.Sprintf("  object_classes = [ %s ]\n", strings.Join(classes, ", ")))
						if attributes, ok := d.GetOk("attributes"); ok {
							attributes := attributes.(map[string]interface{})
							if len(attributes) > 0 {
								//  attributes = [
								file.WriteString("  attributes = [\n")
								for k, v := range attributes {
									values := strings.Split(v.(string), delim)
									for _, value := range values {
										//    { sn = "Doe" },
										file.WriteString(fmt.Sprintf("    { %s = %q },\n", k, value))
									}
								}
								// ]
								file.WriteString("  ]\n")
							}
						}
						file.WriteString("}\n")
					}
				}
			}
		}
	}
	imported = append(imported, d)
	return
}

func resourceLDAPObjectExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	conn := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::exists - checking if %q exists", dn)

	// search by primary key (that is, set the DN as base DN and use a "base
	// object" scope); no attributes are retrieved since we are onòy checking
	// for existence; all objects have an "objectClass" attribute, so the filter
	// is a "match all"
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	)

	_, err := conn.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				log.Printf("[WARN] ldap_object::exists - lookup for %q returned no value: deleted on server?", dn)
				return false, nil
			}
		}
		log.Printf("[DEBUG] ldap_object::exists - lookup for %q returned an error %v", dn, err)
		return false, err
	}

	log.Printf("[DEBUG] ldap_object::exists - object %q exists", dn)
	return true, nil
}

func resourceLDAPObjectCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::create - creating a new object under %q", dn)

	request := ldap.NewAddRequest(dn)

	// retrieve classe from HCL
	objectClasses := []string{}
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		log.Printf("[DEBUG] ldap_object::create - object %q has class: %q", dn, oc.(string))
		objectClasses = append(objectClasses, oc.(string))
	}
	request.Attribute("objectClass", objectClasses)

	// if there is a non empty list of attributes, loop though it and
	// create a new map collecting attribute names and its value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an appareent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(map[string]interface{})
		if len(attributes) > 0 {
			log.Printf("[DEBUG] ldap_object::create - object %q has %d attributes", dn, len(attributes))
			m := make(map[string][]string)
			for k, v := range attributes {
				values := strings.Split(v.(string), delim)
				log.Printf("[DEBUG] ldap_object::create - %q has attribute %s with %d values", dn, k, len(values))
				// each map should only have one entry (see resource declaration)
				for _, value := range values {
					log.Printf("[DEBUG] ldap_object::create - %q has attribute[%v] => %v (%T)", dn, k, value, value)
					m[k] = append(m[k], value)
				}
			}
			// now loop through the map and add attributes with theys value(s)
			for name, values := range m {
				request.Attribute(name, values)
			}
		}
	}

	err := client.Add(request)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] ldap_object::create - object %q added to LDAP server", dn)

	d.SetId(dn)
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectRead(d *schema.ResourceData, meta interface{}) error {
	return readLDAPObjectImpl(d, meta, true)
}

func resourceLDAPObjectUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)

	log.Printf("[DEBUG] ldap_object::update - performing update on %q", d.Id())

	request := ldap.NewModifyRequest(d.Id())

	// handle objectClasses
	if d.HasChange("object_classes") {
		classes := []string{}
		for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
			classes = append(classes, oc.(string))
		}
		log.Printf("[DEBUG] ldap_object::update - updating classes of %q, new value: %v", d.Id(), classes)
		request.ReplaceAttributes = []ldap.PartialAttribute{
			{
				Type: "objectClass",
				Vals: classes,
			},
		}
	}

	if d.HasChange("attributes") {

		o, n := d.GetChange("attributes")
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("old attributes map", o))
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("new attributes map", n))

		added, changed, removed, err := computeDeltas(o.(map[string]interface{}), n.(map[string]interface{}))
		if err != nil {
			log.Printf("[ERROR] ldap_object::update - error diffing LDAP object %q with values %v", d.Id(), err)
			return err
		}
		if len(added) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes added", len(added))
			request.AddAttributes = added
		}
		if len(changed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes changed", len(changed))
			if request.ReplaceAttributes == nil {
				request.ReplaceAttributes = changed
			} else {
				request.ReplaceAttributes = append(request.ReplaceAttributes, changed...)
			}
		}
		if len(removed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes removed", len(removed))
			request.DeleteAttributes = removed
		}
	}

	err := client.Modify(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::update - error modifying LDAP object %q with values %v", d.Id(), err)
		return err
	}
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::delete - removing %q", dn)

	request := ldap.NewDelRequest(dn, nil)

	err := client.Del(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::delete - error removing %q: %v", dn, err)
		return err
	}
	log.Printf("[DEBUG] ldap_object::delete - %q removed", dn)
	return nil
}

func resourceLDAPObjectFind(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	baseDN := d.Get("base_dn").(string)

	log.Printf("[DEBUG] ldap_object::find - looking for objects in %q", baseDN)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
	request := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)

	sr, err := client.Search(request)
	if err != nil {
		log.Printf("[DEBUG] ldap_object::find- lookup for %q returned an error %v", baseDN, err)
		return err
	}

	log.Printf("[DEBUG] ldap_object::find - found %d entries", len(sr.Entries))

	objects := []map[string]interface{}{}

	for _, entry := range sr.Entries {
		log.Printf("[DEBUG] ldap_object::find - found %s", entry.DN)
		oc := []string{}
		attrs := map[string]string{}

		for _, attribute := range entry.Attributes {

			if attribute.Name == "objectClass" {
				oc = attribute.Values
				continue
			}

			if len(attribute.Values) == 1 {
				// we don't treat the RDN as an ordinary attribute
				a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
				if strings.HasPrefix(entry.DN, a) {
					log.Printf("[DEBUG] ldap_object::read - skipping RDN %q of %q", a, entry.DN)
					continue
				}
			}

			attrs[attribute.Name] = strings.Join(attribute.Values, ";")

		}

		objects = append(objects, map[string]interface{}{
			"dn":             entry.DN,
			"object_classes": oc,
			"attributes":     attrs,
		})

	}

	if err := d.Set("objects", objects); err != nil {
		return fmt.Errorf("[WARN] Error setting DNs: %s", err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return nil
}

func readLDAPObjectImpl(d *schema.ResourceData, meta interface{}, updateState bool) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectclass=*)",
		[]string{"*"},
		nil,
	)

	sr, err := client.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 && updateState { // no such object
				log.Printf("[WARN] ldap_object::read - object not found, removing %q from state because it no longer exists in LDAP", dn)
				d.SetId("")
				return nil
			}
		}
		log.Printf("[DEBUG] ldap_object::read - lookup for %q returned an error %v", dn, err)
		return err
	}

	log.Printf("[DEBUG] ldap_object::read - query for %q returned %v", dn, sr)

	d.SetId(dn)
	d.Set("object_classes", sr.Entries[0].GetAttributeValues("objectClass"))

	// now deal with attributes
	attrs := map[string]interface{}{}

	for _, attribute := range sr.Entries[0].Attributes {
		log.Printf("[DEBUG] ldap_object::read - treating attribute %q of %q (%d values: %v)", attribute.Name, dn, len(attribute.Values), attribute.Values)
		if attribute.Name == "objectClass" {
			// skip: we don't treat object classes as ordinary attributes
			log.Printf("[DEBUG] ldap_object::read - skipping attribute %q of %q", attribute.Name, dn)
			continue
		}
		if len(attribute.Values) == 1 {
			// we don't treat the RDN as an ordinary attribute
			a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
			if strings.HasPrefix(dn, a) {
				log.Printf("[DEBUG] ldap_object::read - skipping RDN %q of %q", a, dn)
				continue
			}
		}
		log.Printf("[DEBUG] ldap_object::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
		// now add each value as an individual entry into the object, because
		// we do not handle name => []values, and we have a set of maps each
		// holding a single entry name => value; multiple maps may share the
		// same key.
		attrs[attribute.Name] = strings.Join(attribute.Values, ";")
	}

	if err := d.Set("attributes", attrs); err != nil {
		log.Printf("[WARN] ldap_object::read - error setting LDAP attributes for %q : %v", dn, err)
		return err
	}
	return nil
}

func printAttributes(prefix string, attributes interface{}) string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%s: {\n", prefix))
	if attributes, ok := attributes.(map[string]interface{}); ok {
		for k, v := range attributes {
			values := v.(*schema.Set).List()
			for _, value := range values {
				buffer.WriteString(fmt.Sprintf("    %q: %q\n", k, value.(string)))
			}
		}
		buffer.WriteRune('}')
	}
	return buffer.String()
}

func computeDeltas(om, nm map[string]interface{}) (added, changed, removed []ldap.PartialAttribute, err error) {
	var changelog diff.Changelog

	changelog, err = diff.Diff(om, nm)
	if err != nil {
		return
	}

	for _, change := range changelog {
		if change.Type == "delete" {
			if len(change.Path) == 1 {
				// Case: Top level attribute removed
				removed = append(removed, ldap.PartialAttribute{
					Type: change.Path[0],
					Vals: []string{},
				})

			} else if len(change.Path) == 2 {
				// Case: Attribute value removed
				changed = append(changed, ldap.PartialAttribute{
					Type: change.Path[0],
					Vals: []string{change.To.(string)},
				})

			}
		}

		if change.Type == "create" {
			if len(change.Path) == 1 {
				added = append(added, ldap.PartialAttribute{
					Type: change.Path[0],
					Vals: change.To.([]string),
				})
			} else {
				changed = append(changed, ldap.PartialAttribute{
					Type: change.Path[0],
					Vals: []string{change.To.(string)},
				})
			}
		}
	}

	return
}
