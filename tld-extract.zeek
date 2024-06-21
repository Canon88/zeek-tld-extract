module TldExtract;

export {
    # Define a record type for extracting names
    type EffectiveNames: record {
        tld: string &optional;
        domain: string &optional;
        subdomain: string &optional;
    };

    # Declare global functions for extracting parts of the DNS query
    global effective_tld_parts: function(domain: string): count;
    global effective_tld: function(domain: string): string;
    global effective_domain: function(domain: string): string;
    global effective_subdomain: function(domain: string): string;
    global effective_names: function(domain: string): EffectiveNames;

    # Declare options for TLD sets
    option first_TLD_set: set[string] = set();
    option second_TLD_set: set[string] = set();
    option third_TLD_set: set[string] = set();
    option fourth_TLD_set: set[string] = set();
    option trusted_tlds_set: set[string] = set();
    option trusted_domains_set: set[string] = set();
    option trusted_querys_set: set[string] = set();
}

# Define regex pattern placeholders to find TLDs
global effective_tlds_1st_level: pattern = /./ &redef;
global effective_tlds_2nd_level: pattern = /./ &redef;
global effective_tlds_3rd_level: pattern = /./ &redef;
global effective_tlds_4th_level: pattern = /./ &redef;
const effective_tld_local: pattern = /(.*(\.local))|(^[^\.]+)$/;

# Define regex patterns for domain and top level domains
const extraction_regex: table[count] of pattern = {
    [1] = /\.[^\.]+$/,
    [2] = /\.[^\.]+\.[^\.]+$/,
    [3] = /\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [4] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [5] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [6] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]\.[^\.]+$/,
};

########################################################
## begin Input Framework
# Use Input Framework to maintain list of TLDs
type Idx: record {
    tld: string;
};
type Idx_tld: record {
    trusted_tld: string;
};
type Idx_td: record {
    trusted_domain: string;
};
type Idx_tq: record {
    trusted_query: string;
};

# Global sets to hold TLD data
global first_TLD_dat: set[string] = set();
global second_TLD_dat: set[string] = set();
global third_TLD_dat: set[string] = set();
global fourth_TLD_dat: set[string] = set();
global trusted_querys_dat: set[string] = set();
global trusted_domains_dat: set[string] = set();
global trusted_tlds_dat: set[string] = set();
global config_path: string = "/usr/local/zeek/share/zeek/site/input_files/";

event zeek_init() &priority=10 {
    # Add input tables to read TLD data and trusted domains data
    Input::add_table([$source=config_path + "1st_level_public.dat", $name="first_TLD_dat", $idx=Idx, $destination=first_TLD_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "2nd_level_public.dat", $name="second_TLD_dat", $idx=Idx, $destination=second_TLD_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "3rd_level_public.dat", $name="third_TLD_dat", $idx=Idx, $destination=third_TLD_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "4th_level_public.dat", $name="fourth_TLD_dat", $idx=Idx, $destination=fourth_TLD_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "trusted_tlds.dat", $name="trusted_tlds_dat", $idx=Idx_tld, $destination=trusted_tlds_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "trusted_domains.dat", $name="trusted_domains_dat", $idx=Idx_td, $destination=trusted_domains_dat, $mode=Input::REREAD]);
    Input::add_table([$source=config_path + "trusted_querys.dat", $name="trusted_querys_dat", $idx=Idx_tq, $destination=trusted_querys_dat, $mode=Input::REREAD]);

    # Convert TLD sets to regex patterns
    effective_tlds_1st_level = set_to_regex(first_TLD_dat, "\\.(~~)$");
    effective_tlds_2nd_level = set_to_regex(second_TLD_dat, "\\.(~~)$");
    effective_tlds_3rd_level = set_to_regex(third_TLD_dat, "\\.(~~)$");
    effective_tlds_4th_level = set_to_regex(fourth_TLD_dat, "\\.(~~)$");
}
## end Input Framework
########################################################

# Function to determine the number of parts in the TLD
function effective_tld_parts(query: string): count {
    local tld_parts = 1;
    local dot_query = "." + query;

    # Find how many parts are in the TLD.
    if (effective_tlds_4th_level in dot_query)
        tld_parts = 4;
    else if (effective_tlds_3rd_level in dot_query)
        tld_parts = 3;
    else if (effective_tlds_2nd_level in dot_query)
        tld_parts = 2;

    return tld_parts;
}

# Function to extract the TLD from the DNS query
function effective_tld(query: string): string {
    local tld_parts = effective_tld_parts(query);
    local tld_raw = find_last("." + query, extraction_regex[tld_parts]);
    return lstrip(tld_raw, "\\.");
}

# Function to extract the domain from the DNS query
function effective_domain(query: string): string {
    local tld_parts = effective_tld_parts(query);
    local domain_raw = find_last("." + query, extraction_regex[tld_parts + 1]);
    return lstrip(domain_raw, "\\.");
}

# Function to extract the subdomain from the DNS query
function effective_subdomain(query: string): string {
    local tld_parts = effective_tld_parts(query);
    return sub(query, extraction_regex[tld_parts + 1], "");
}

# Function to extract all parts (TLD, domain, subdomain) from the DNS query
function effective_names(query: string): EffectiveNames {
    if (effective_tld_local in query) {
        return EffectiveNames($tld="local", $domain="local", $subdomain="");
    }

    local tld = effective_tld(query);
    if (tld == "in-addr.arpa") {
        return EffectiveNames($tld=tld, $domain="in-addr.arpa", $subdomain="");
    } else if (tld == query) {
        return EffectiveNames($tld=tld, $domain=query, $subdomain="");
    }

    local domain = effective_domain(query);
    if (domain == query) {
        return EffectiveNames($tld=tld, $domain=query, $subdomain="");
    }

    local subdomain = effective_subdomain(query);
    return EffectiveNames($tld=tld, $domain=domain, $subdomain=subdomain);
}

########################################################
## begin set_to_regex
# Convert TLD sets to regex as they are updated
event Input::end_of_data(name: string, source: string) {
    if (name == "first_TLD_dat") {
        effective_tlds_1st_level = set_to_regex(first_TLD_dat, "\\.(~~)$");
        Config::set_value("TldExtract::first_TLD_set", first_TLD_dat);
    }

    if (name == "second_TLD_dat") {
        effective_tlds_2nd_level = set_to_regex(second_TLD_dat, "\\.(~~)$");
        Config::set_value("TldExtract::second_TLD_set", second_TLD_dat);
    }

    if (name == "third_TLD_dat") {
        effective_tlds_3rd_level = set_to_regex(third_TLD_dat, "\\.(~~)$");
        Config::set_value("TldExtract::third_TLD_set", third_TLD_dat);
    }

    if (name == "fourth_TLD_dat") {
        effective_tlds_4th_level = set_to_regex(fourth_TLD_dat, "\\.(~~)$");
        Config::set_value("TldExtract::fourth_TLD_set", fourth_TLD_dat);
    }

    if (name == "trusted_tlds_dat") {
        Config::set_value("TldExtract::trusted_tlds_set", trusted_tlds_dat);
    }

    if (name == "trusted_domains_dat") {
        Config::set_value("TldExtract::trusted_domains_set", trusted_domains_dat);
    }

    if (name == "trusted_querys_dat") {
        Config::set_value("TldExtract::trusted_querys_set", trusted_querys_dat);
    }
}
## end set_to_regex
########################################################
