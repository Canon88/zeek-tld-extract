module DomainRank;

# Extend the DNS::Info record to include custom fields
redef record DNS::Info += {
    ## The rank of the domain based on the publicsuffix.org top-level domain database.
    rank: count &log &optional; # Optional field to log the rank of the domain
};

# Event to handle DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! c?$dns )
        return;
    
    # Check if the query domain is in the top N table
    if ( query in top_n_table )
        {
        # Assign the rank from the top N table to the DNS connection's rank field
        c$dns$rank = top_n_table[query]$rank;
        }
    # Check if the domain part of the DNS connection is in the top N table
    else if ( (c$dns?$domain) && (c$dns$domain in top_n_table) )
        {
        # Assign the rank from the top N table to the DNS connection's rank field
        c$dns$rank = top_n_table[c$dns$domain]$rank;
        }
    # Check if the top-level domain part of the DNS connection is in the top N table
    else if ( (c$dns?$tld) && (c$dns$tld in top_n_table) )
        {
        # Assign the rank from the top N table to the DNS connection's rank field
        c$dns$rank = top_n_table[c$dns$tld]$rank;
        }
    }
