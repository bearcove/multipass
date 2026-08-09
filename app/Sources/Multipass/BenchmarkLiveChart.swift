import SwiftUI

struct BenchmarkLiveChart: View {
    let samples: [Double]

    var body: some View {
        Canvas { context, size in
            guard samples.count > 1, let peak = samples.max(), peak > 0 else { return }
            let xStep = size.width / CGFloat(max(samples.count - 1, 1))
            var path = Path()
            for (index, sample) in samples.enumerated() {
                let x = CGFloat(index) * xStep
                let y = size.height - CGFloat(sample / peak) * size.height
                if index == 0 {
                    path.move(to: CGPoint(x: x, y: y))
                } else {
                    path.addLine(to: CGPoint(x: x, y: y))
                }
            }
            context.stroke(path, with: .foreground, lineWidth: 2)
        }
        .foregroundStyle(Color.accentColor)
        .frame(minHeight: 72, idealHeight: 92, maxHeight: 112)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilitySummary)
    }

    private var accessibilitySummary: String {
        guard let current = samples.last, let peak = samples.max() else {
            return "Live throughput graph, waiting for samples"
        }
        return "Live throughput graph, current \(BenchmarkFormatting.gbitsPerSecond(current)), peak \(BenchmarkFormatting.gbitsPerSecond(peak)), \(samples.count) one-second samples"
    }
}
