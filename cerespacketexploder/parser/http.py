#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import magic
import moment
# Local import
from parser import parser
from ..utils import utils
from ..observable import observable

"""http parser"""

class http(parser):
    """
    http parser
    """

    explode_result = None

    def explode(self):
        """
        Execute chaosreader and parse generate files to extract observables
        """

        # Execute chaosreader
        os.system('{crbin} -v "{pcap}" -D "{dest}" > {output}'.format(
            dest=self.storage+'/'+os.path.basename(self.pcap_filename)+".sessions", pcap=self.pcap_filename, crbin=os.path.realpath(self.config['chaosreader']), output=self.storage+'/chaosreader.log'
        ))

        session_id = []
        pcapsessiondir = self.storage+'/' + os.path.basename(self.pcap_filename)+".sessions/"

        # Retrieve all session files
        if(os.path.exists(pcapsessiondir)):
            files = [f for f in os.listdir(pcapsessiondir) if os.path.isfile(
                os.path.join(pcapsessiondir, f))]
            for file in files:
                if str(file).startswith('session_'):
                    matches = re.search(r"session_(\d+)\.info", file)
                    if matches:
                        session_id += [matches.group(1)]
            session_id = sorted(session_id)

        # For each session file
        sessions = []
        for sessid in session_id:
            if True:

                # Get the main information

                info = utils.file_get_contents(
                    pcapsessiondir+"session_"+sessid+".info")
                info = (info.split('\n'))

                data = []
                data += [('Session', sessid)]
                for line in info[2:-1]:
                    linesplited = line.split(': ')
                    key = linesplited[0].strip().replace(' ', '_')
                    value = linesplited[1].strip()
                    data += [(key, value)]
                cursess = dict(data)


                # If session is http : analyze the session
                if cursess['Dest_service'] == 'http':

                    # Retrieve the http requests and responses

                    raw = utils.file_get_contents(pcapsessiondir+"session_"+sessid+".http.html")
                    raw = raw.replace('<font color="green">', '')
                    raw = raw.replace('<font color="red">', '')
                    raw = raw.replace('<font color="blue">', '')
                    raw = raw.replace('&gt;</font>', '')
                    raw = raw.replace('</font>', '')
                    raw = raw.replace('\n', '')
                    raw = raw.replace('\r', '\n')

                    # Isolate requests and reponses
                    matches = re.finditer(r"(^([A-z0-9\-]+)(\:\s)(.*))|(([A-Z]+)\s(\S+)\s((HTTP)\/\d\.\d))|(((HTTP)\/\d\.\d)\s(\d+)\s(.+))", raw, re.MULTILINE)

                    RequestE = {}
                    current = "Request"
                    id = 0
                    # Associate request with response
                    for matchNum, match in enumerate(matches):
                        matchNum = matchNum + 1

                        if(match.group(9) == 'HTTP'):
                            # Request
                            id += 1
                            current = "Request"
                            RequestE['{}-{}'.format(sessid, id)] = {
                                "Request": {
                                    "Method": match.group(6),
                                    "Url": match.group(7),
                                    "Proto": match.group(8),
                                    "Headers": {}
                                },
                                "Response": {}
                            }
                        elif(match.group(12) == 'HTTP' and id != 0):
                            current = "Response"
                            RequestE['{}-{}'.format(sessid, id)]['Response'] = {
                                "Status": {
                                    "Code": match.group(13),
                                    "Message": match.group(14),
                                },
                                "Proto": match.group(11),
                                "Headers": {}
                            }
                        else:
                            if(match.group(2) != '' and id != 0):
                                RequestE['{}-{}'.format(
                                    sessid, id)][current]['Headers'][match.group(2)] = match.group(4)

                    cursess['Http'] = RequestE


                    # For each Request-Response, retrieve files
                    for sessionHttp in cursess['Http']:
                        cursessHttp = cursess['Http'][sessionHttp]
                        cursess['Http'][sessionHttp]['Dropped_files'] = []
                        file_id = int(sessionHttp.split('-')[1])
                        if(file_id < 10):
                            file_id = '0{}'.format(file_id)
                        file_dname = 'session_{}.part_{}'.format(
                            sessid, file_id)
                        
                        # For each dropped files
                        for findF in files:
                            if(findF.startswith(file_dname)):
                                
                                # Find the filename
                                filename = None

                                # Filename in headers
                                if cursess['Http'][sessionHttp]['Response'].get('Headers') and cursess['Http'][sessionHttp]['Response']['Headers'].get('Content-Disposition'):
                                    contentDisposition = cursess['Http'][sessionHttp]['Response']['Headers'].get(
                                        'Content-Disposition').split('filename=')
                                    filename = contentDisposition[1].strip()
                                # Filename in url
                                else:
                                    matches = re.search(r"(([A-z0-9\-\_\%]+\.\S*?))(\?\S*)?$", cursess['Http'][sessionHttp]['Request']['Url'])
                                    if matches:
                                        filename = matches.group(2)
                                
                                # Save file info
                                findFpath = pcapsessiondir+findF
                                cursess['Http'][sessionHttp]['Dropped_files'] += [{
                                    "path": findFpath,
                                    "mime": magic.from_file(findFpath, mime=True),
                                    "filename": filename,
                                    "hash": {
                                        "sha256": utils.file_hash('sha256', findFpath),
                                        "md5": utils.file_hash('md5', findFpath)
                                    }
                                }]

                    sessions += [cursess]

        # Construct the final collections
        outraw = {}
        for session in sessions:
            if(session.get('Http') and session.get('Http') != None):
                for idpart in (session.get('Http')):

                    outraw[session['Session']] = {}
                    outraw[session['Session']]['fqdn'] = {}
                    
                    part = session['Http'].get(idpart)

                    fqdn_l = part['Request']['Headers']['Host'].split('.')
                    fqdn = '{}.{}'.format(fqdn_l[-2], fqdn_l[-1])

                    if(fqdn not in outraw):
                        outraw[session['Session']]['fqdn'][fqdn] = {'domain': {}, 'ip': {}}

                    outraw[session['Session']]['fqdn'][fqdn]['domain'][str(part['Request']['Headers']['Host'])] = {}

                    outraw[session['Session']]['ip'] = list(set([
                        session.get('Source_addr'),
                        session.get('Dest_addr')
                    ]))

                    outraw[session['Session']]['date'] = list(set([
                        session.get('First_time'),
                        session.get('Last_time')
                    ]))

                    url = part['Request']['Url']
                    if not url.startswith('http://'):
                        url = 'http://'+part['Request']['Headers']['Host']+url

                    outraw[session['Session']]['fqdn'][fqdn]['domain'][str(
                        part['Request']['Headers']['Host'])][url] = {}

                    for dfile in part['Dropped_files']:
                        outraw[session['Session']]['fqdn'][fqdn]['domain'][str(part['Request']['Headers']['Host'])][url][dfile['path']] = {
                            "hash": dfile['hash'],
                            "filename": dfile['filename']
                        }

        self.explode_result = outraw


    def report(self):
        outraw = self.explode_result
        outfinal0 = []
        for session in outraw:
            outfinal1 = []
            for fqdn in outraw[session]['fqdn']:
                for domain in outraw[session]['fqdn'][fqdn]['domain']:
                    for url in outraw[session]['fqdn'][fqdn]['domain'][domain]:
                        for file in outraw[session]['fqdn'][fqdn]['domain'][domain][url]:
                            filechild = outraw[session]['fqdn'][fqdn]['domain'][domain][url][file]
                            for hashd in filechild['hash']:
                                outfinal1 += [observable(filechild['hash'].get(hashd), 'hash').__dict__]
                            if(filechild['filename'] != None):
                                outfinal1 += [observable(filechild['filename'], 'filename').__dict__]
                            outfinal1 += [observable(file, 'file').__dict__]
                        outfinal1 += [observable(url, 'url').__dict__]
                    outfinal1 += [observable(domain, 'domain').__dict__]
                for ip in outraw[session]['ip']:
                    outfinal1 += [observable(ip, 'ip').__dict__]
                for date in outraw[session]['date']:
                    m = moment.date(date, '%a %b %d $H:$M:$S %Y')
                    outfinal1 += [observable(m.format('YYYY-MM-DD HH:mm:ss'), 'date').__dict__]        
                outfinal1 += [observable(fqdn, 'fqdn').__dict__]
            outfinal0 += [observable(session, 'session', outfinal1).__dict__]
        return outfinal0



    