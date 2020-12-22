use strict;
use warnings;

# Functional functions - Main control flow

sub get_counts {
    my %filters = get_filters();

    open(APACHEFILE, "apache_log_sample.txt") or die "failed to open apache log file: $!";
    open(APACHEANALYSISFILE, ">apache_log_data.txt") or die "failed to open apache log analysis file: $!";

    while ( (my $filter_type, my $filter) = each %filters ){
        my %filter_data;

        foreach my $apache_data (<APACHEFILE>) {
            my $filter_data_get = $filter -> ($apache_data);

            $filter_data_get = !defined $filter_data_get ? "!no value!" : $filter_data_get;

            $filter_data{$filter_data_get}++;
        }

        print APACHEANALYSISFILE "\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t------$filter_type------\n";

        while ( (my $filter_value, my $found_count) = each %filter_data){
            print APACHEANALYSISFILE "\nValue: $filter_value Found: $found_count\n";
        }

        seek APACHEFILE, 0, 0;
        print APACHEANALYSISFILE "\n";
    }
}


# Helper functions - Denoise additional required functionality from the main flow.

sub get_filters {
    # Apache log example: 66.249.73.135 - - [17/May/2015:17:05:54 +0000] "GET /blog/geekery/grok-and-eventdb.html HTTP/1.1" 200 12456 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    # Apache log format: remotehost rfc931 authuser [date] "request" status bytes
    
    my $get_request_url = sub { my ( $request_url ) = $_[0] =~ /(?:GET|POST)\s{1}(.*?)\s/; return $request_url; };
    my $get_status_code = sub { my ( $status_code ) = $_[0] =~ /"\s{1}(.*?)\s{1}.*?\s{1}(?:"http|"-)/; return $status_code; };
    my $get_bytes_output = sub{ my ( $bytes_output ) = $_[0] =~ /"\s{1}.*?\s{1}(.*?)\s{1}(?:"http|"-)/; return $bytes_output; };

    my %filters_hash = (
        "Request URLs" => $get_request_url,
        "Status Codes" => $get_status_code,
        "Bytes Output" => $get_bytes_output
    );

    return %filters_hash;
}

get_counts();