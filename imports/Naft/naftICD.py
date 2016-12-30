#!/usr/bin/env python

__description__ = 'Network Appliance Forensic Toolkit - IOS Core Dumps'
__author__ = 'Didier Stevens'
__version__ = '0.0.9'
__date__ = '2015/02/10'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/12/05: start
  2011/12/06: continue
  2011/12/12: continue
  2012/01/25: refactoring for cIOSCoreDump
  2012/01/26: IOSCWStrings
  2012/01/27: Added command processes
  2012/01/29: Added option minimum
  2012/01/30: Continue processes
  2012/01/31: Continue processes
  2012/02/01: refactoring
  2012/02/13: V0.0.3: dProcessStructureStats
  2012/02/15: heuristics
  2012/02/20: V0.0.5: added IOSHistory
  2012/02/22: added IOSEvents, refactoring
  2013/03/30: added IOSCheckText
  2013/03/31: continued IOSCheckText
  2014/05/03: V0.0.6: added handling of sreloc in IOSCheckText
  2014/09/19: V0.0.7: updated IOSFrames
  2014/10/23: V0.0.9: option -w now also for heap command
  2014/10/24: added option -D and command integritycheck
  2015/02/10: added YARA support

Todo:
"""

import optparse
import struct
import re
import sys
import os
import binascii
import naft_uf
import naft_impf
import naft_pfef
import naft_iipf
try:
    import yara
except:
    pass

def IOSRegions(coredumpFilename):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    returnString = ''
    if oIOSCoreDump.error  != '':
        returnString+= (oIOSCoreDump.error)
    else:
        returnString+=('Start      End        Size       Name <br>')
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                returnString+= ('0x%08X 0x%08X %10d %s <br>' % (region[1], region[1] + region[2] - 1, region[2], region[0]))
                #if options.write:
                 #   naft_uf.Data2File(oIOSCoreDump.Region(region[0])[1], '%s-%s-0x%08X' % (coredumpFilename, region[0], region[1]))
            else:
                returnString+= ('0x%08X %s %s <br>' % (region[1], ' ' * 21, region[0]))
        addressBSS, dataBSS = oIOSCoreDump.RegionBSS()
    return returnString
    

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('<br>'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def YARACompile(fileordirname):
    dFilepaths = {}
    if os.path.isdir(fileordirname):
        for root, dirs, files in os.walk(fileordirname):
            for file in files:
                filename = os.path.join(root, file)
                dFilepaths[filename] = filename
    else:
        for filename in ProcessAt(fileordirname):
            dFilepaths[filename] = filename
    return yara.compile(filepaths=dFilepaths)

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec open(decoder, 'r') in globals(), globals()
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e

class cIdentity(cDecoderParent):
    name = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ''

def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()

def IOSHeap(coredumpFilename,options):
    global decoders
    decoders = []
    LoadDecoders(options.decoders, True)
    returnString = ''

    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return returnString
        rules = YARACompile(options.yara)

    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        returnString+=(oIOSCoreDump.error) 
        return returnString
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        returnString += ('Heap region not found')
        return returnString
    oIOSMemoryParser = naft_impf.cIOSMemoryParser(memoryHeap)
    if options.resolve or options.filter != '':
        oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    if options.filter == '':
        if options.write:    
            print(naft_impf.cIOSMemoryBlockHeader.ShowHeader)
            for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
                print(oIOSMemoryBlockHeader.ShowLine())
                naft_uf.Data2File(oIOSMemoryBlockHeader.GetData(), '%s-heap-0x%08X.data' % (coredumpFilename, oIOSMemoryBlockHeader.address))
        elif options.yara:
            print(naft_impf.cIOSMemoryBlockHeader.ShowHeader)
            for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
                linePrinted = False
                oDecoders = [cIdentity(oIOSMemoryBlockHeader.GetData(), None)]
                for cDecoder in decoders:
                    try:
                        oDecoder = cDecoder(oIOSMemoryBlockHeader.GetData(), options.decoderoptions)
                        oDecoders.append(oDecoder)
                    except Exception as e:
                        print('Error instantiating decoder: %s' % cDecoder.name)
                        raise e
                for oDecoder in oDecoders:
                    while oDecoder.Available():
                        for result in rules.match(data=oDecoder.Decode()):
                            if not linePrinted:
                                print(oIOSMemoryBlockHeader.ShowLine())
                                linePrinted = True
                            print(' YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (decoder: %s)' % oDecoder.Name()), result.rule))
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('  %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('  %s' % binascii.hexlify(stringdata[2]))
                                    print('  %s' % repr(stringdata[2]))
    
        else:
            returnString += oIOSMemoryParser.Show()
    else:        
        returnString += (naft_impf.cIOSMemoryBlockHeader.ShowHeader) + '<br>'
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == options.filter:
                if not options.strings:
                    returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
                if options.strings:
                    dStrings = naft_uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
                    if options.grep != '':
                        printHeader = True
                        for key, value in dStrings.items():
                            if value.find(options.grep) >= 0:
                                if printHeader:
                                    returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
                                    printHeader = False
                                returnString +=(' %08X: %s<br>' % (oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value))
                    elif options.minimum == 0 or len(dStrings) >= options.minimum:
                        returnString += (oIOSMemoryBlockHeader.ShowLine())+ '<br>'
                        for key, value in dStrings.items():
                            returnString +=(' %08X: %s<br>' % (oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value))
                if options.dump:
                    naft_uf.DumpBytes(oIOSMemoryBlockHeader.GetData(), oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.headerSize)
                if options.dumpraw:
                    naft_uf.DumpBytes(oIOSMemoryBlockHeader.GetRawData(), oIOSMemoryBlockHeader.address)
                    if options.write:
                        naft_uf.Data2File(oIOSMemoryBlockHeader.GetData(), '%s-heap-0x%08X.data' % (coredumpFilename, oIOSMemoryBlockHeader.address))
    return returnString

def IOSFrames(coredumpFilename, filenameIOMEM, filenamePCAP, options):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParserHeap = naft_impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParserHeap.ResolveNames(oIOSCoreDump)
    dataIOMEM = naft_uf.File2Data(filenameIOMEM)
    oIOSMemoryParserIOMEM = naft_impf.cIOSMemoryParser(dataIOMEM)
    addressIOMEM = oIOSMemoryParserIOMEM.baseAddress
    if addressIOMEM == None:
        print('Error parsing IOMEM')
        return
    oFrames = naft_pfef.cFrames()
    print(naft_impf.cIOSMemoryBlockHeader.ShowHeader)
    for oIOSMemoryBlockHeader in oIOSMemoryParserHeap.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == '*Packet Header*':
            frameAddress = struct.unpack('>I', oIOSMemoryBlockHeader.GetData()[40:44])[0]
            frameSize = struct.unpack('>H', oIOSMemoryBlockHeader.GetData()[72:74])[0]
            if frameSize <= 1:
                frameSize = struct.unpack('>H', oIOSMemoryBlockHeader.GetData()[68:70])[0]
            if frameAddress != 0 and frameSize != 0:
                print(oIOSMemoryBlockHeader.ShowLine())
                naft_uf.DumpBytes(dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], frameAddress)
                oFrames.AddFrame(frameAddress - addressIOMEM, dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], True)
    oFrames.WritePCAP(filenamePCAP)

def IOSCWStringsSub(data):
    returnString=''
    oCWStrings = naft_impf.cCiscoCWStrings(data)
    if oCWStrings.error != '':
        returnString+=(oCWStrings.error)
        return
    keys = oCWStrings.dCWStrings.keys()
    keys.sort()
    for key in keys:
        if key == 'CW_SYSDESCR': 
            returnString+=('%s:<br>' % key)
            returnString+=(oCWStrings.dCWStrings[key]+'<br>')
        else:
            returnString+=('%s:%s%s<br>' % (key, ' ' * (22 - len(key)), oCWStrings.dCWStrings[key]))
    return returnString

def IOSCWStrings(coredumpFilename):
    returnString = ''
#    if options.raw:
#        coredump = naft_uf.File2Data(coredumpFilename)
#        if coredump == None:
#            print('Error reading file %s' % coredumpFilename)
#        else:
#            IOSCWStringsSub(coredump)
    
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        returnString+=(oIOSCoreDump.error)
        return
    addressData, memoryData = oIOSCoreDump.RegionDATA()
    if memoryData == None:
        returnString+=('Data region not found')
        return
    returnString+=IOSCWStringsSub(memoryData)
    return returnString

def PrintStatsAnalysis(dStats, oIOSCoreDump):
    keys1 = dStats.keys()
    keys1.sort()
    for key1 in keys1:
        countKeys = len(dStats[key1])
        keys2 = dStats[key1].keys()
        keys2.sort()
        if countKeys > 2 and countKeys <= 7:
            bucket = '-> ' + ' '.join(['%X:%d' % (key2, dStats[key1][key2]) for key2 in keys2])
        else:
            bucket = ''
        filtered = filter(lambda x: x != 0, dStats[key1])
        if filtered == []:
            filteredMin = min(dStats[key1])
        else:
            filteredMin = min(filtered)
        unfilteredMax = max(dStats[key1])
        regionNames = []
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                if filteredMin >= region[1] and filteredMin <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
                if unfilteredMax >= region[1] and unfilteredMax <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
        regionNames.sort()
        regionName = ' '.join(regionNames).strip()
        print('%3d %3X: %3d %08X %08X %08X %s %s' % (key1, key1*4, countKeys, min(dStats[key1]), filteredMin, unfilteredMax, regionName, bucket))

def IOSProcesses(coredumpFilename, options):
    returnString = ''
    oIOSCoreDumpAnalysis = naft_impf.cIOSCoreDumpAnalysis(coredumpFilename)
    if oIOSCoreDumpAnalysis.error != '':
        returnString += (oIOSCoreDumpAnalysis.error)
        return returnString

    for (processID, addressProcess, oIOSProcess) in oIOSCoreDumpAnalysis.processes:
        if options.filter == '' or processID == int(options.filter):
            if oIOSProcess != None:
                if oIOSProcess.error == '':
                    line = oIOSProcess.Line()
                else:
                    line = '%4d %s' % (processID, oIOSProcess.error)
                returnString += (line)+ '<br>'
                if options.dump:
                    naft_uf.DumpBytes(oIOSProcess.data, addressProcess)
            else:
                returnString += ('addressProcess not found %d %08X <br>' % (processID, addressProcess))

    if oIOSCoreDumpAnalysis.RanHeuristics:
        returnString += ('<br>')
        returnString += ('*** WARNING ***<br>')
        returnString += ('Unexpected process structure<br>')
        returnString += ('Please reports these results<br>')
        returnString += ('Fields determined with heuristics:<br>')
        returnString += ('Process structure size: %d<br>' % oIOSCoreDumpAnalysis.HeuristicsSize)
        keys = oIOSCoreDumpAnalysis.HeuristicsFields.keys()
        keys.sort(key=str.lower)
        for key in keys:
            value = oIOSCoreDumpAnalysis.HeuristicsFields[key]
            if value != None:
                returnString += ('%-22s: 0x%04X <br>' % (key, value[1]))

    if options.statistics:
        keys = oIOSCoreDumpAnalysis.dProcessStructureStats.keys()
        keys.sort()
        returnString += ('Number of different process structures: %d<br>' % len(keys))
        for index in keys:
            returnString += ('Process structures length: %d<br>' % index)
            PrintStatsAnalysis(oIOSCoreDumpAnalysis.dProcessStructureStats[index], oIOSCoreDumpAnalysis.oIOSCoreDump)
    return returnString


def FilterInitBlocksForString(coredumpFilename, searchTerm):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        #print(oIOSCoreDump.error)
        return []
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return []
    oIOSMemoryParser = naft_impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    found = []
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == 'Init':
            dStrings = naft_uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
            for value in dStrings.values():
                if value.find(searchTerm) >= 0:
                    found.append(value)
    return found

def IOSHistory(coredumpFilename, options=None):
    history = []
    returnString = ''
    for command in FilterInitBlocksForString(coredumpFilename, 'CMD: '):
        oMatch = re.search("'(.+)' (.+)", command)
        if oMatch:
            history.append((oMatch.group(2), oMatch.group(1)))
    for command in sorted(history, key=lambda x: x[0]):
        returnString += ('%s: %s<br>' % command)
    return returnString

def IOSEvents(coredumpFilename, options=None):
    returnString = ''
    for event in sorted(FilterInitBlocksForString(coredumpFilename, ': %')):
        returnString += (event) + '<br>'
    return returnString

def IOSCheckText(coredumpFilename, imageFilename, options):
    returnString = ''
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        returnString += (oIOSCoreDump.error) + '<br>'
        return returnString
    else:
        textAddress, textCoredump = oIOSCoreDump.RegionTEXT()
        if textCoredump == None:
            returnString += ('Error extracting text region from coredump %s<br>' % coredumpFilename)
            return returnString
        sysdescrCoredump = ''
        dataAddress, dataCoredump = oIOSCoreDump.RegionDATA()
        if dataCoredump != None:
            oCWStrings = naft_impf.cCiscoCWStrings(dataCoredump)
            if oCWStrings.error == '' and 'CW_SYSDESCR' in oCWStrings.dCWStrings:
                sysdescrCoredump = oCWStrings.dCWStrings['CW_SYSDESCR']

    image = naft_uf.File2Data(imageFilename)
    if image == None:
        returnString += ('Error reading image %s' % imageFilename)
        return returnString

    oIOSImage = naft_iipf.cIOSImage(image)
    if oIOSImage.error != 0:
        return
    sysdescrImage = ''
    if oIOSImage.oCWStrings != None and oIOSImage.oCWStrings.error == '' and 'CW_SYSDESCR' in oIOSImage.oCWStrings.dCWStrings:
        sysdescrImage = oIOSImage.oCWStrings.dCWStrings['CW_SYSDESCR']
    if sysdescrCoredump != '' or sysdescrImage != '':
        if sysdescrCoredump == sysdescrImage:
            returnString += ('CW_SYSDESCR are identical:<br>')
            returnString += (sysdescrCoredump) + '<br>'
        elif sysdescrCoredump == sysdescrImage.replace('-MZ', '-M', 1):
            returnString += ('CW_SYSDESCR are equivalent:<br>')
            returnString += (sysdescrCoredump)+ '<br>'
        else:
            returnString += ('CW_SYSDESCR are different:<br>')
            returnString += (sysdescrCoredump) +'<br>'
            returnString += '<br>'
            returnString += (sysdescrImage) + '<br>'
        returnString += '<br>'

    oELF = naft_iipf.cELF(oIOSImage.imageUncompressed)
    if oELF.error != 0:
        returnString +=('ELF parsing error %d.' % oELF.error)
        return returnString
    countSectionExecutableInstructions = 0
    countSectionSRELOC = 0
    for oSectionHeader in oELF.sections:
        if oSectionHeader.flags & 4: # SHF_EXECINSTR executable instructions
            textSectionData = oSectionHeader.sectionData
            countSectionExecutableInstructions += 1
        if oSectionHeader.nameIndexString == 'sreloc':
            countSectionSRELOC += 1
    if countSectionExecutableInstructions != 1:
        returnString += ('Error executable sections in image: found %d sections, expected 1' % countSectionExecutableInstructions)
        return returnString
    if countSectionSRELOC != 0:
        returnString += ('Error found %d sreloc section in image: checktext command does not support relocation' % countSectionSRELOC)
        return returnString 
    start = textAddress & 0xFF # to be further researched
    textImage = textSectionData[start:start + len(textCoredump)]
    if len(textCoredump) != len(textImage):
        returnString += ('the text region is longer than the text section<br>')
        returnString += ('len(textCoredump) = %d<br>' % len(textCoredump))
        returnString += ('len(textImage) = %d<br>' % len(textImage))
    countBytesDifferent = 0
    shortestLength = min(len(textCoredump), len(textImage))
    for iIter in range(shortestLength):
        if textCoredump[iIter] != textImage[iIter]:
            if countBytesDifferent == 0:
                returnString += ('text region and section are different starting 0x%08X in coredump (iter = 0x%08X)<br>' % ((textAddress + iIter), iIter))
            countBytesDifferent += 1
    if countBytesDifferent == 0:
        returnString += ('text region and section are identical <br>')
    else:
        returnString += ('number of different bytes: %d (%.2f%%)<br>' % (countBytesDifferent, (countBytesDifferent * 100.0) / shortestLength))

    return returnString

# http://phrack.org/issues/60/7.html
def IOSIntegrityText(coredumpFilename, options):
    returnString = ''
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        returnString += (oIOSCoreDump.error)
        return returnString
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        returnString +=('Heap region not found')
        return returnString
    oIOSMemoryParser = naft_impf.cIOSMemoryParser(memoryHeap)
    returnString += ('Check start magic:<br>')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.GetRawData()[0:4] != naft_impf.cCiscoMagic.STR_BLOCK_BEGIN:
            returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
            hit = True
    if not hit:
        returnString += ('OK<br>')
    returnString += ('Check end magic:<br>')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if struct.unpack('>I', oIOSMemoryBlockHeader.GetRawData()[-4:])[0] != naft_impf.cCiscoMagic.INT_BLOCK_CANARY and oIOSMemoryBlockHeader.RefCnt > 0:
            returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
            hit = True
    if not hit:
        returnString += ('OK<br>')
    returnString += ('Check previous block:<br>')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[1:]:
        if oIOSMemoryBlockHeader.PrevBlock == 0:
            returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
            hit = True
    if not hit:
        returnString += ('OK<br>')
    returnString += ('Check next block: <br>')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[:-1]:
        if oIOSMemoryBlockHeader.NextBlock == 0:
            returnString += (oIOSMemoryBlockHeader.ShowLine()) + '<br>'
            hit = True
    if not hit:
        returnString += ('OK<br>')

    return returnString


def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] command arguments ...<br>' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='dump data')
    oParser.add_option('-D', '--dumpraw', action='store_true', default=False, help='dump raw data')
    oParser.add_option('-s', '--strings', action='store_true', default=False, help='dump strings in data')
    oParser.add_option('-m', '--minimum', type=int, default=0, help='minimum count number of strings')
    oParser.add_option('-g', '--grep', default='', help='grep strings')
    oParser.add_option('-r', '--resolve', action='store_true', default=False, help='resolve names')
    oParser.add_option('-f', '--filter', default='', help='filter for given name')
    oParser.add_option('-a', '--raw', action='store_true', default=False, help='search in the whole file for CW_ strings')
    oParser.add_option('-w', '--write', action='store_true', default=False, help='write the regions or heap blocks to disk')
    oParser.add_option('-t', '--statistics', action='store_true', default=False, help='Print process structure statistics')
    oParser.add_option('-y', '--yara', help='YARA rule (or directory or @file) to check heaps')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    (options, args) = oParser.parse_args()

    dCommands = {
                    'regions':        (2, IOSRegions,       'coredump: identify regions in core dump, options w'),
                    'cwstrings':      (2, IOSCWStrings,     'coredump: extract CW_ strings, options a'),
                    'heap':           (2, IOSHeap,          'coredump: list heap linked list, options rfdsgmwDy'),
                    'history':        (2, IOSHistory,       'coredump: list command history'),
                    'events':         (2, IOSEvents,        'coredump: list events'),
                    'frames':         (4, IOSFrames,        'coredump iomem pcap-file: extract frames and store them in pcap-file'),
                    'processes':      (2, IOSProcesses,     'coredump: list processes, options fdt'),
                    'checktext':      (3, IOSCheckText,     'coredump image: compare the text section in memory and image'),
                    'integritycheck': (2, IOSIntegrityText, 'coredump: check the integrity of the heap'),
                }

    if len(args) == 0:
        oParser.print_help()
        print('')
        print('Commands:')
        for command, config in dCommands.items():
            print('  %s %s' % (command, config[2]))
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif not args[0] in dCommands:
        print('unknown command')
        return

    if len(args) == dCommands[args[0]][0]:
        dCommands[args[0]][1](*(args[1:] + [options]))
    else:
        print('Error: expected %d arguments, you provided %d arguments' % (dCommands[args[0]][0], len(args)))

if __name__ == '__main__':
    Main()
