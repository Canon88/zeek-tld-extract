module TldExtract;

export {
    # Option to enable_module or disable tld extract features.
    option enable_module: set[string] = {};

    # Including a custom configuration file for tld extract.
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/tld-extract/config.dat" };
}

@load ./plugins/dns