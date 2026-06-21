package acme

// DNSField describes one credential a lego DNS provider needs.
type DNSField struct {
	Key      string `json:"key"`      // environment variable name lego reads
	Label    string `json:"label"`    // human label
	Secret   bool   `json:"secret"`   // render as a password field, store encrypted
	Optional bool   `json:"optional"` // not required
	Help     string `json:"help,omitempty"`
}

// DNSProviderSpec is one selectable provider in the UI dropdown.
type DNSProviderSpec struct {
	Code   string     `json:"code"`  // lego provider code passed to NewDNSChallengeProviderByName
	Label  string     `json:"label"` // display name
	Fields []DNSField `json:"fields"`
	Docs   string     `json:"docs"`
}

// DNSProviderCatalog returns a curated set of the most common lego DNS providers
// with the exact credential fields each one needs. lego supports 100+ providers;
// this is the popular subset surfaced as a guided form. Any other provider can
// still be configured via the "Other" option using raw KEY=value pairs, so the
// dropdown never limits what is actually possible.
//
// Field/env-var names are taken from lego's provider documentation:
// https://go-acme.github.io/lego/dns/
func DNSProviderCatalog() []DNSProviderSpec {
	return []DNSProviderSpec{
		{Code: "cloudflare", Label: "Cloudflare", Docs: "https://go-acme.github.io/lego/dns/cloudflare/", Fields: []DNSField{
			{Key: "CF_DNS_API_TOKEN", Label: "API Token", Secret: true, Help: "Scoped token with Zone:DNS:Edit. Recommended."},
		}},
		{Code: "route53", Label: "AWS Route 53", Docs: "https://go-acme.github.io/lego/dns/route53/", Fields: []DNSField{
			{Key: "AWS_ACCESS_KEY_ID", Label: "Access Key ID", Secret: true},
			{Key: "AWS_SECRET_ACCESS_KEY", Label: "Secret Access Key", Secret: true},
			{Key: "AWS_REGION", Label: "Region", Optional: true, Help: "e.g. us-east-1"},
			{Key: "AWS_HOSTED_ZONE_ID", Label: "Hosted Zone ID", Optional: true},
		}},
		{Code: "gcloud", Label: "Google Cloud DNS", Docs: "https://go-acme.github.io/lego/dns/gcloud/", Fields: []DNSField{
			{Key: "GCE_PROJECT", Label: "GCP Project ID"},
			{Key: "GCE_SERVICE_ACCOUNT", Label: "Service Account JSON", Secret: true, Help: "Full service-account JSON contents."},
		}},
		{Code: "azuredns", Label: "Azure DNS", Docs: "https://go-acme.github.io/lego/dns/azuredns/", Fields: []DNSField{
			{Key: "AZURE_CLIENT_ID", Label: "Client ID"},
			{Key: "AZURE_CLIENT_SECRET", Label: "Client Secret", Secret: true},
			{Key: "AZURE_TENANT_ID", Label: "Tenant ID"},
			{Key: "AZURE_SUBSCRIPTION_ID", Label: "Subscription ID"},
			{Key: "AZURE_RESOURCE_GROUP", Label: "Resource Group", Optional: true},
		}},
		{Code: "digitalocean", Label: "DigitalOcean", Docs: "https://go-acme.github.io/lego/dns/digitalocean/", Fields: []DNSField{
			{Key: "DO_AUTH_TOKEN", Label: "API Token", Secret: true},
		}},
		{Code: "hetzner", Label: "Hetzner", Docs: "https://go-acme.github.io/lego/dns/hetzner/", Fields: []DNSField{
			{Key: "HETZNER_API_KEY", Label: "API Key", Secret: true},
		}},
		{Code: "gandiv5", Label: "Gandi (LiveDNS)", Docs: "https://go-acme.github.io/lego/dns/gandiv5/", Fields: []DNSField{
			{Key: "GANDIV5_PERSONAL_ACCESS_TOKEN", Label: "Personal Access Token", Secret: true},
		}},
		{Code: "godaddy", Label: "GoDaddy", Docs: "https://go-acme.github.io/lego/dns/godaddy/", Fields: []DNSField{
			{Key: "GODADDY_API_KEY", Label: "API Key", Secret: true},
			{Key: "GODADDY_API_SECRET", Label: "API Secret", Secret: true},
		}},
		{Code: "namecheap", Label: "Namecheap", Docs: "https://go-acme.github.io/lego/dns/namecheap/", Fields: []DNSField{
			{Key: "NAMECHEAP_API_USER", Label: "API User"},
			{Key: "NAMECHEAP_API_KEY", Label: "API Key", Secret: true},
		}},
		{Code: "namedotcom", Label: "Name.com", Docs: "https://go-acme.github.io/lego/dns/namedotcom/", Fields: []DNSField{
			{Key: "NAMECOM_USERNAME", Label: "Username"},
			{Key: "NAMECOM_API_TOKEN", Label: "API Token", Secret: true},
		}},
		{Code: "linode", Label: "Linode (Akamai)", Docs: "https://go-acme.github.io/lego/dns/linode/", Fields: []DNSField{
			{Key: "LINODE_TOKEN", Label: "API Token", Secret: true},
		}},
		{Code: "vultr", Label: "Vultr", Docs: "https://go-acme.github.io/lego/dns/vultr/", Fields: []DNSField{
			{Key: "VULTR_API_KEY", Label: "API Key", Secret: true},
		}},
		{Code: "ovh", Label: "OVH", Docs: "https://go-acme.github.io/lego/dns/ovh/", Fields: []DNSField{
			{Key: "OVH_ENDPOINT", Label: "Endpoint", Help: "e.g. ovh-eu"},
			{Key: "OVH_APPLICATION_KEY", Label: "Application Key", Secret: true},
			{Key: "OVH_APPLICATION_SECRET", Label: "Application Secret", Secret: true},
			{Key: "OVH_CONSUMER_KEY", Label: "Consumer Key", Secret: true},
		}},
		{Code: "dnsimple", Label: "DNSimple", Docs: "https://go-acme.github.io/lego/dns/dnsimple/", Fields: []DNSField{
			{Key: "DNSIMPLE_OAUTH_TOKEN", Label: "OAuth Token", Secret: true},
		}},
		{Code: "desec", Label: "deSEC", Docs: "https://go-acme.github.io/lego/dns/desec/", Fields: []DNSField{
			{Key: "DESEC_TOKEN", Label: "API Token", Secret: true},
		}},
		{Code: "duckdns", Label: "DuckDNS", Docs: "https://go-acme.github.io/lego/dns/duckdns/", Fields: []DNSField{
			{Key: "DUCKDNS_TOKEN", Label: "Token", Secret: true},
		}},
		{Code: "porkbun", Label: "Porkbun", Docs: "https://go-acme.github.io/lego/dns/porkbun/", Fields: []DNSField{
			{Key: "PORKBUN_API_KEY", Label: "API Key", Secret: true},
			{Key: "PORKBUN_SECRET_API_KEY", Label: "Secret API Key", Secret: true},
		}},
		{Code: "bunny", Label: "Bunny.net", Docs: "https://go-acme.github.io/lego/dns/bunny/", Fields: []DNSField{
			{Key: "BUNNY_API_KEY", Label: "API Key", Secret: true},
		}},
		{Code: "njalla", Label: "Njalla", Docs: "https://go-acme.github.io/lego/dns/njalla/", Fields: []DNSField{
			{Key: "NJALLA_TOKEN", Label: "Token", Secret: true},
		}},
		{Code: "netcup", Label: "Netcup", Docs: "https://go-acme.github.io/lego/dns/netcup/", Fields: []DNSField{
			{Key: "NETCUP_CUSTOMER_NUMBER", Label: "Customer Number"},
			{Key: "NETCUP_API_KEY", Label: "API Key", Secret: true},
			{Key: "NETCUP_API_PASSWORD", Label: "API Password", Secret: true},
		}},
		{Code: "inwx", Label: "INWX", Docs: "https://go-acme.github.io/lego/dns/inwx/", Fields: []DNSField{
			{Key: "INWX_USERNAME", Label: "Username"},
			{Key: "INWX_PASSWORD", Label: "Password", Secret: true},
		}},
		{Code: "scaleway", Label: "Scaleway", Docs: "https://go-acme.github.io/lego/dns/scaleway/", Fields: []DNSField{
			{Key: "SCW_ACCESS_KEY", Label: "Access Key"},
			{Key: "SCW_SECRET_KEY", Label: "Secret Key", Secret: true},
		}},
		{Code: "exoscale", Label: "Exoscale", Docs: "https://go-acme.github.io/lego/dns/exoscale/", Fields: []DNSField{
			{Key: "EXOSCALE_API_KEY", Label: "API Key", Secret: true},
			{Key: "EXOSCALE_API_SECRET", Label: "API Secret", Secret: true},
		}},
		{Code: "transip", Label: "TransIP", Docs: "https://go-acme.github.io/lego/dns/transip/", Fields: []DNSField{
			{Key: "TRANSIP_ACCOUNT_NAME", Label: "Account Name"},
			{Key: "TRANSIP_PRIVATE_KEY_PATH", Label: "Private Key Path", Help: "Path to the private key inside the container."},
		}},
		{Code: "pdns", Label: "PowerDNS", Docs: "https://go-acme.github.io/lego/dns/pdns/", Fields: []DNSField{
			{Key: "PDNS_API_URL", Label: "API URL"},
			{Key: "PDNS_API_KEY", Label: "API Key", Secret: true},
		}},
		{Code: "rfc2136", Label: "RFC2136 (dynamic DNS)", Docs: "https://go-acme.github.io/lego/dns/rfc2136/", Fields: []DNSField{
			{Key: "RFC2136_NAMESERVER", Label: "Nameserver", Help: "host:port"},
			{Key: "RFC2136_TSIG_KEY", Label: "TSIG Key Name"},
			{Key: "RFC2136_TSIG_SECRET", Label: "TSIG Secret", Secret: true},
			{Key: "RFC2136_TSIG_ALGORITHM", Label: "TSIG Algorithm", Optional: true, Help: "e.g. hmac-sha256."},
		}},
	}
}
