import ConfigParser
import grequests
import json
import sys
from logger import get_logger
import logging
from parsers import zeustracker
from parsers import sans
from parsers import nothink_malware_dns
from parsers import alienvault
from parsers import malwaredomainslist

logger = get_logger('reaper')

def exception_handler(request, exception):
    logger.error("Request %r failed: %r" % (request, exception))

def reap(file_name):
    config = ConfigParser.SafeConfigParser(allow_no_value=False)
    cfg_success = config.read('combine.cfg')
    if not cfg_success:
        logger.error('Reaper: Could not read combine.cfg.')
        logger.error('HINT: edit combine-example.cfg and save as combine.cfg.')
        return

    # reading feeds configuration
    feeds_conf = ConfigParser.SafeConfigParser(allow_no_value=False)
    fcfg_success = feeds_conf.read('feeds.cfg')
    
    if not fcfg_success:
        logger.error('Reaper: Could not read feeds.cfg.')
        logger.error('HINT: make sure there is a feeds configuration file in the folder')
        return
    
    # note - make sure to get the file 
    logger.info('Fetching URLs')
    reqs=[]
    harvest=[]
    headers = {'User-Agent': 'Combine/0.1.1'}
    feed_index={}
    for feed in feeds_conf.sections():
        if feed != "_default" and not feed in globals().keys():
            logger.error("Reaper: Don't know what to do with the following feed: %s" % feed)
        elif feed != "_default":
            url=feeds_conf.get(feed,'reference').rstrip('\n')
            feed_index[url]=feed
            if url[0:4] == 'file':
                try:
                    with open(url.partition('://')[2],'rb') as f:
                        harvest.append([feed, 200, f.read()])
                except IOError as e:
                    assert isinstance(logger, logging.Logger)
                    logger.error('Reaper: Error while opening "%s" - %s' % (each, e.strerror))
            else:
                reqs.append(grequests.get(url, headers=headers))
    responses = grequests.map(reqs, exception_handler=exception_handler)
    harvest += [(feed_index[response.url], response.status_code, response.text) for response in responses if response]
    logger.error('Storing raw feeds in %s' % file_name)
    with open(file_name, 'wb') as f:
        json.dump(harvest, f, indent=2)
    """
    inbound_files=[]
    for url in inbound_urls:
        if url.startswith('file://'):
            inbound_files.append(url.partition('://')[2])
            inbound_urls.remove(url)
    
    
    reqs = [grequests.get(url, headers=headers) for url in inbound_urls]
    inbound_responses = grequests.map(reqs, exception_handler=exception_handler)
    inbound_harvest = [(response.url, response.status_code, response.text) for response in inbound_responses if response]
    for each in inbound_files:
        try:
            with open(each,'rb') as f:
                inbound_harvest.append(('file://'+each, 200, f.read()))
        except IOError as e:
            assert isinstance(logger, logging.Logger)
            logger.error('Reaper: Error while opening "%s" - %s' % (each, e.strerror))

    logger.info('Fetching outbound URLs')
    
    outbound_files=[]
    for url in outbound_urls:
        if url.startswith('file://'):
            outbound_files.append(url.partition('://')[2])
            outbound_urls.remove(url)
    reqs = [grequests.get(url, headers=headers) for url in outbound_urls]
    outbound_responses = grequests.map(reqs, exception_handler=exception_handler)
    outbound_harvest = [(response.url, response.status_code, response.text) for response in outbound_responses if response]
    for each in outbound_files:
        try:
            with open(each,'rb') as f:
                outbound_harvest.append(('file://'+each, 200, f.read()))
        except IOError as e:
            assert isinstance(logger, logging.Logger)
            logger.error('Reaper: Error while opening "%s" - %s' % (each, e.strerror))

    logger.error('Storing raw feeds in %s' % file_name)
    harvest = {'inbound': inbound_harvest, 'outbound': outbound_harvest}

    with open(file_name, 'wb') as f:
        json.dump(harvest, f, indent=2)
    """

if __name__ == "__main__":
    reap('harvest.json')
