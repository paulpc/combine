import ConfigParser
import bs4
import datetime
import json
import re
import sys
from logger import get_logger
import logging
from parsers import zeustracker
from parsers import sans
from parsers import nothink_malware_dns
from parsers import alienvault
from parsers import malwaredomainslist

logger = get_logger('thresher')



def thresh(input_file, output_file):

    config = ConfigParser.SafeConfigParser(allow_no_value=False)
    cfg_success = config.read('combine.cfg')
    if not cfg_success:
        logger.error('Thresher: Could not read combine.cfg.')
        logger.error('HINT: edit combine-example.cfg and save as combine.cfg.')
        return

    logger.info('Loading raw feed data from %s' % input_file)
    with open(input_file, 'rb') as f:
        crop = json.load(f)

    harvest = []
    # TODO: replace with a proper plugin system (cf. #23)
    """thresher_map = {'blocklist.de': generic.process_simple_list,
                    'openbl': generic.process_simple_list,
                    'projecthoneypot': project_honeypot.process,
                    'ciarmy': generic.process_simple_list,
                    'alienvault': alienvault.process,
                    'rulez': rulez.process,
                    'sans': sans.process,
                    'http://www.nothink.org/blacklist/blacklist_ssh': generic.process_simple_list,
                    'http://www.nothink.org/blacklist/blacklist_malware': generic.process_simple_list,
                    'abuse.ch': generic.process_simple_list,
                    'packetmail': packetmail.process,
                    'autoshun': autoshun.process,
                    'the-haleys': haleys.process,
                    'virbl': generic.process_simple_list,
                    'dragonresearchgroup': drg.process,
                    'malwaregroup': malwaregroup.process,
                    'malc0de': generic.process_simple_list,
                    'file://': generic.process_simple_list}"""

    # When we have plugins, this hack won't be necessary
    #for response in crop['inbound']:
    for response in crop:
        logger.info('Evaluating %s' % response[0])
        # TODO: logging
        if response[1] == 200:
            harvest+=globals()[response[0]].process(response[2])
            #for site in thresher_map:
                #if site in response[0]:
                #    logger.info('Parsing feed from %s' % response[0])
                #    harvest += thresher_map[site](response[2], response[0], 'inbound')
                #else:  # how to handle non-mapped sites?
                #    pass
        else:  # how to handle non-200 non-404?
            logger.error('Could not handle %s: %s' % (response[0], response[1]))

    """for response in crop['outbound']:
        if response[1] == 200:
            for site in thresher_map:
                if site in response[0]:
                    logger.info('Parsing feed from %s' % response[0])
                    harvest += thresher_map[site](response[2], response[0], 'outbound')
                else:  # how to handle non-mapped sites?
                    pass
        else:  # how to handle non-200 non-404?
            pass
"""
    logger.info('Storing parsed data in %s' % output_file)
    with open(output_file, 'wb') as f:
        json.dump(harvest, f, indent=2)


if __name__ == "__main__":
    thresh('harvest.json', 'crop.json')
