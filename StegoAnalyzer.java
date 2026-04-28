import java.awt.image.BufferedImage;

/**
 * Simple statistical stego analyzer.
 * Produces channel-level metrics and a confidence score.
 */
public class StegoAnalyzer {

    public static class Report {
        public double lsbRatioR;
        public double lsbRatioG;
        public double lsbRatioB;
        public double chiR;
        public double chiG;
        public double chiB;
        public double entropy;
        public double transitionRatio;
        public long headerLength;
        public boolean headerPlausible;
        public double confidence;
        public String verdict;

        @Override
        public String toString() {
            return "StegoAnalyzer.Report{" +
                    "lsbRatioR=" + lsbRatioR +
                    ", lsbRatioG=" + lsbRatioG +
                    ", lsbRatioB=" + lsbRatioB +
                    ", chiR=" + chiR +
                    ", chiG=" + chiG +
                    ", chiB=" + chiB +
                    ", entropy=" + entropy +
                    ", transitionRatio=" + transitionRatio +
                    ", headerLength=" + headerLength +
                    ", headerPlausible=" + headerPlausible +
                    ", confidence=" + confidence +
                    ", verdict='" + verdict + '\'' +
                    '}';
        }
    }

    public static Report analyze(BufferedImage img) {
        int[] freqR = new int[256];
        int[] freqG = new int[256];
        int[] freqB = new int[256];

        long bitsR = 0, bitsG = 0, bitsB = 0;
        long onesR = 0, onesG = 0, onesB = 0;
        long transitions = 0, compared = 0;
        int prevBit = -1;
        long headerLen = 0;
        int headerBits = 0;

        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                freqR[r]++;
                freqG[g]++;
                freqB[b]++;

                int[] channels = {r, g, b};
                for (int c = 0; c < channels.length; c++) {
                    int bit = channels[c] & 1;
                    if (c == 0) {
                        bitsR++;
                        if (bit == 1) onesR++;
                    } else if (c == 1) {
                        bitsG++;
                        if (bit == 1) onesG++;
                    } else {
                        bitsB++;
                        if (bit == 1) onesB++;
                    }

                    if (prevBit != -1) {
                        if (prevBit != bit) transitions++;
                        compared++;
                    }
                    prevBit = bit;

                    if (headerBits < 32) {
                        headerLen = ((headerLen << 1) | bit) & 0xFFFFFFFFL;
                        headerBits++;
                    }
                }
            }
        }

        Report report = new Report();
        report.lsbRatioR = ratio(onesR, bitsR);
        report.lsbRatioG = ratio(onesG, bitsG);
        report.lsbRatioB = ratio(onesB, bitsB);
        report.chiR = normalizedChi(freqR);
        report.chiG = normalizedChi(freqG);
        report.chiB = normalizedChi(freqB);
        report.entropy = lsbEntropy(onesR + onesG + onesB, bitsR + bitsG + bitsB);
        report.transitionRatio = ratio(transitions, compared);
        report.headerLength = headerLen & 0xFFFFFFFFL;

        long maxPayload = (img.getWidth() * (long) img.getHeight() * 3L) / 8L - 4L;
        report.headerPlausible = report.headerLength >= 40L && report.headerLength <= maxPayload;

        double avgLsb = (report.lsbRatioR + report.lsbRatioG + report.lsbRatioB) / 3.0;
        double balanceIndicator = clamp01(1.0 - Math.abs(avgLsb - 0.5) * 2.0);
        double chiIndicator = (report.chiR + report.chiG + report.chiB) / 3.0;
        double entropyIndicator = clamp01(report.entropy);
        double transitionIndicator = clamp01(1.0 - Math.abs(report.transitionRatio - 0.5) * 2.0);
        double headerIndicator = report.headerPlausible ? 1.0 : 0.0;
        if (report.headerPlausible && maxPayload > 0) {
            double sizeRatio = (double) report.headerLength / (double) maxPayload;
            if (sizeRatio > 0.98) headerIndicator *= 0.8;
            if (report.headerLength < 56) headerIndicator *= 0.85;
        }

        report.confidence = clamp01(
                0.18 * chiIndicator +
                0.07 * balanceIndicator +
                0.05 * entropyIndicator +
                0.05 * transitionIndicator +
                0.65 * headerIndicator
        ) * 100.0;
        report.verdict = classify(report.confidence);
        return report;
    }

    private static double ratio(long n, long d) {
        if (d <= 0) return 0.0;
        return (double) n / (double) d;
    }

    private static double normalizedChi(int[] freq) {
        double chi = 0.0;
        double total = 0.0;
        for (int i = 0; i < 256; i += 2) {
            double a = freq[i];
            double b = freq[i + 1];
            double sum = a + b;
            total += sum;
            if (sum > 0) {
                double diff = a - b;
                chi += (diff * diff) / sum;
            }
        }
        if (total == 0.0) return 0.0;

        // Soft normalization to 0..1 for a stable confidence blend.
        double norm = chi / total;
        return clamp01(1.0 - Math.exp(-6.0 * norm));
    }

    private static double lsbEntropy(long ones, long total) {
        if (total <= 0) return 0.0;
        double p1 = (double) ones / (double) total;
        double p0 = 1.0 - p1;
        return entropyTerm(p0) + entropyTerm(p1);
    }

    private static double entropyTerm(double p) {
        if (p <= 0.0) return 0.0;
        return -p * (Math.log(p) / Math.log(2));
    }

    private static String classify(double score) {
        if (score >= 72.0) return "Likely hidden data";
        if (score >= 45.0) return "Suspicious";
        return "Likely clean";
    }

    private static double clamp01(double v) {
        if (v < 0.0) return 0.0;
        if (v > 1.0) return 1.0;
        return v;
    }
}
