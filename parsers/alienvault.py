from generic import indicator_type
from generic import headless_xsv
import datetime
import ConfigParser

def process(response):
    """ processes the alienvault data"""
    
    #203.121.165.16#6#5#C&C#TH##15.0,100.0#2
    #108.59.1.5#4#2#Scanning Host#A1##0.0,0.0#11
    
    headers=['ipv4-addr','reliability','priority','description','country','city','lat-long','misc']
    feeds_conf = ConfigParser.SafeConfigParser(allow_no_value=False)
    fcfg_success = feeds_conf.read('feeds.cfg')
    
    if not fcfg_success:
        logger.error('Reaper: Could not read feeds.cfg.')
        logger.error('HINT: make sure there is a feeds configuration file in the folder')
        return
    settings={}
    settings['confidence']=feeds_conf.get('alienvault','confidence')
    settings['impact']=feeds_conf.get('alienvault','impact')
    settings['campaign']=feeds_conf.get('alienvault','campaign')
    settings['type']=feeds_conf.get('alienvault','type')
    settings['reference']=feeds_conf.get('alienvault','reference')
    
    data = []
    for row in headless_xsv(response,headers,'#'):
        date=datetime.datetime.now()
        # judging the confidence
        if int(row['reliability']) <4:
            confidence='low'
        elif int(row['reliability']) <8:
            confidence='medium'
        else:
            confidence='high'
        # judging the impact
        if int(row['priority']) <4:
            impact='low'
        elif int(row['priority']) <8:
            impact='medium'
        else:
            impact='high'
        # looking at the description
        if row['description']:
            desc=row['description']
        else:
            desc=settings['type']
        
        data.append({'value':row['ipv4-addr'],'type':'ipv4-addr','description':desc,'date':'%s' % date,'confidence':confidence,'impact':impact,'campaign':settings['campaign'],'reference':settings['reference']})

    return data

"""if not line.startswith('#') and len(line) > 0:
            i = line.partition('#')[0].strip()
            note = line.split('#')[3].strip()
            if 'Scanning Host' in note or 'Spamming' in note:
                direction = 'inbound'
            elif 'Malware' in note or 'C&C' in note or 'APT' in note:
                direction = 'outbound'
            data.append((i, indicator_type(i), direction, source, note, '%s' % datetime.date.today()))
"""