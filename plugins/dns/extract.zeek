module TldExtract;

# Extend the DNS::Info record to include custom fields
redef record DNS::Info += {
	## Indicates if the domain is trusted based on a manually created list of domains.
	is_trusted_domain: bool &log &default=F;

	## Indicates if the domain is a local domain.
	is_local_domain: bool &log &default=F;

	## Based on the publicsuffix.org top-level domain database, the remainder of the FQDN after the domain.
	## This could be a hostname or a subdomain with a hostname.
	subdomain: string &log &optional;

	## The domain, based on the publicsuffix.org top-level domain database.
	domain: string &log &optional;

	## The top-level domain, based on the publicsuffix.org top-level domain database.
	tld: string &log &optional;
};

# Event handler for DNS requests
# Uses the regex patterns from the TLD lists to find the number of parts in the TLD
# and uses the appropriate regex pattern to extract the desired values.
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
    if ( ! c?$dns )
        return;
    
	# Check if the DNS module is enabled
	if ( "DNS" !in enable_module )
		return;

	# Use the TldExtract module to extract TLD, domain, and subdomain from the query
	local result = effective_names(query);
	c$dns$tld = result$tld;
	c$dns$domain = result$domain;
	c$dns$subdomain = result$subdomain;

	# Check if the domain is trusted
	if ( ( c$dns$domain == "local" )
	    || ( c$dns$domain == "in-addr.arpa" )
	    || ( c$dns$domain in trusted_domains_set )
	    || ( c$dns$tld in trusted_tlds_set )
	    || ( query in trusted_querys_set ) )
		{
		c$dns$is_trusted_domain = T;
		}

	# Check if the query is a local domain
	if ( ( Site::is_local_name(query) )
	    || ( query in local_querys_set )
	    || ( c$dns$domain in local_domains_set )
	    || ( c$dns$tld in local_tlds_set ) )
		{
		c$dns$is_local_domain = T;
		}
	}
