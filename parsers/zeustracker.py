from generic import indicator_type

def process(response):
    """ processes the sans data"""
    data = []
    headers=['ipv4-addr','attacks','asn','first_seen','last_seen']
    feeds_conf = ConfigParser.SafeConfigParser(allow_no_value=False)
    fcfg_success = feeds_conf.read('feeds.cfg')
    
    if not fcfg_success:
        logger.error('Reaper: Could not read feeds.cfg.')
        logger.error('HINT: make sure there is a feeds configuration file in the folder')
        return
    settings={}
    settings['confidence']=feeds_conf.get('sans','confidence')
    settings['impact']=feeds_conf.get('sans','impact')
    settings['campaign']=feeds_conf.get('sans','campaign')
    settings['type']=feeds_conf.get('sans','type')
    
    for row in headless_xsv(response,headers,"\t"):
         # converting the date field 2014/12/03_08:50
        if row['date']:
            date=datetime.datetime.strptime(row['last_seen'],'%Y-%m-%d')
        else:
            date=datetime.date.today()
        data.append({'value':row['ipv4-addr'],'type':'ipv4-addr','description':settings['type'],'date':'%s' % date,'confidence':settings['confidence'],'impact':settings['impact'],'campaign':settings['campaign']})
    return data