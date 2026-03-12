package org.example;

import org.example.engine.DPIEngine;
import java.util.*;

public class Main {

    private static void printUsage(String program) {

        System.out.println("""
Usage:
  """ + program + " <input.pcap> <output.pcap> [options]\n" +

"""
Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (YouTube, Facebook)
  --block-domain <dom>   Block domain
  --rules <file>         Load rules from file
  --lbs <n>              Number of load balancers
  --fps <n>              FP threads per LB
  --verbose              Enable verbose mode
""");
    }

    public static void main(String[] args) {

        if (args.length < 2) {
            printUsage("java Main");
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        String rulesFile = null;

        for (int i = 2; i < args.length; i++) {

            String arg = args[i];

            switch (arg) {

                case "--block-ip":
                    if (i + 1 < args.length)
                        blockIps.add(args[++i]);
                    break;

                case "--block-app":
                    if (i + 1 < args.length)
                        blockApps.add(args[++i]);
                    break;

                case "--block-domain":
                    if (i + 1 < args.length)
                        blockDomains.add(args[++i]);
                    break;

                case "--rules":
                    if (i + 1 < args.length)
                        rulesFile = args[++i];
                    break;

                case "--lbs":
                    if (i + 1 < args.length)
                        config.numLoadBalancers = Integer.parseInt(args[++i]);
                    break;

                case "--fps":
                    if (i + 1 < args.length)
                        config.fpsPerLb = Integer.parseInt(args[++i]);
                    break;

                case "--verbose":
                    config.verbose = true;
                    break;

                case "--help":
                case "-h":
                    printUsage("java Main");
                    return;
            }
        }

        DPIEngine engine = new DPIEngine(config);

        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            return;
        }

        if (rulesFile != null) {
            engine.loadRules(rulesFile);
        }

        for (String ip : blockIps)
            engine.blockIP(ip);

        for (String app : blockApps)
            engine.blockApp(app);

        for (String domain : blockDomains)
            engine.blockDomain(domain);

        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            return;
        }

        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }
}