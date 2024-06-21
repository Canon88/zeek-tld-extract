module DomainRank;

# Record type to represent a domain as an index
type Idx: record {
    domain: string;
};

# Record type to represent the rank of a domain
type Val: record {
    rank: count;
};

# Table to store the top N domains and their ranks
global top_n_dat: table[string] of Val = table();

# Path to the input files directory
global config_path: string = "/usr/local/zeek/share/zeek/site/input_files/";

export {
    # Option to maintain the table of top N domains
    option top_n_table: table[string] of Val = table();
}

# Event to initialize the input table during the startup of Zeek
event zeek_init() &priority=10
    {
    # Add input table to read the top N domains data from the specified file
    Input::add_table([ $source=config_path + "top-n.dat", $name="top_n_dat",
        $idx=Idx, $val=Val, $destination=top_n_dat, $mode=Input::REREAD ]); # Load the top 10K data into the table
    }

# Event triggered when input framework has finished reading data
event Input::end_of_data(name: string, source: string)
    {
    if ( name == "top_n_dat" )
        {
        # Update the exported table with the newly read top N domains data
        Config::set_value("DomainRank::top_n_table", top_n_dat);
        }
    }
