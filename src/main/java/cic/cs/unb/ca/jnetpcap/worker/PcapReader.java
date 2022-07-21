package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.*;
import org.jnetpcap.PcapClosedException;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.FILE_SEP;
import static cic.cs.unb.ca.jnetpcap.Utils.FLOW_SUFFIX;
import static cic.cs.unb.ca.jnetpcap.Utils.countLines;

public class PcapReader {


    public static void readFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if (inputFile == null || outPath == null) {
            return;
        }

        //String fileName = FilenameUtils.getName(inputFile);
        Path p = Paths.get(inputFile);
        String fileName = p.getFileName().toString();

        if (!outPath.endsWith(FILE_SEP)) {
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath + fileName + FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Saved file full path cannot be deleted");
            }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName, outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s", fileName));

        int nValid = 0;
        int nTotal = 0;
        int nDiscarded = 0;
        long previousTimestamp = 0;
        long currentTimestamp = 0;
        boolean disordered = false;
        long start = System.currentTimeMillis();
        while (true) {
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if (basicPacket != null) {
                    //
                    // Check that pcap file isn't disordered to make sure to obtain consistent netflows.
                    //
                    currentTimestamp = basicPacket.getTimeStamp();
                    if(previousTimestamp>currentTimestamp){
                        disordered = true;
                        break;
                    }else{
                        previousTimestamp = currentTimestamp;
                    }
                
                    flowGen.addPacket(basicPacket);
                    nValid++;
                } else {
                    nDiscarded++;
                }
            } catch (PcapClosedException e) {
                break;
            }
        }

        if(disordered){
            // The pcap file is disordered don't export network flows.
            System.out.println("/!\\ The pcap file contains disordered packets ! The network flows may be incorrect.");
            System.out.println("Please order your pcap file and run the tool again.");
            System.out.println("----------------------------------------------------------------------------");
        }else{
            // the pcap file is well ordered continue and save network flows.

            flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

            long lines = countLines(saveFileFullPath.getPath());

            System.out.println(String.format("%s is done. total %d flows ", fileName, lines));
            System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d", nTotal, nValid, nDiscarded));
            System.out.println("-----------------------------------------------------------------------------------------");
        }
    }


    static class FlowListener implements FlowGenListener {

        private String fileName;

        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {

            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, fileName + FLOW_SUFFIX);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName, cnt);

            System.out.print(console);
        }
    }
}
