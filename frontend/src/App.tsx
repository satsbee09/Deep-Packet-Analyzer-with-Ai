import { useState } from 'react'
import { AreaChart, Area, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, PieChart, Pie, Cell } from 'recharts'

interface EventItem {
  timestamp: string
  sourceIp: string | null
  sourcePort: number | null
  destinationIp: string | null
  destinationPort: number | null
  protocol: string | null
  applicationProtocol?: string | null
  hostName?: string | null
  serverName?: string | null
  reasons: string[]
  severity: string
  summary: string
}

interface AIPrediction {
  pattern: string
  value: string
  confidence: string
  reason: string
}

interface PatternEntry {
  type: string
  value: string
  count: number
  lastSeen: string | null
}

interface AnalysisSummary {
  totalBlocked: number
  uniqueThreats: number
  threatCounts: Record<string, number>
  severityCounts: Record<string, number>
  httpsCount: number
}

interface MLTopSuspicious {
  packetIndex: number
  score: number
  prediction: number
  srcPort: number
  dstPort: number
  protocol: number
}

interface MLInsights {
  modelLoaded: boolean
  suspiciousCount: number
  averageScore: number
  topSuspicious: MLTopSuspicious[]
}

interface AIInsights {
  predictions: AIPrediction[]
  topPatterns: PatternEntry[]
}

interface AnalysisResult {
  summary: AnalysisSummary
  events: EventItem[]
  aiInsights?: AIInsights
  mlInsights?: MLInsights
}

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const onFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setError(null)
    const selectedFile = event.target.files?.[0] ?? null
    setFile(selectedFile)
  }

  const uploadPcap = async () => {
    if (!file) return
    setLoading(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('http://localhost:8000/upload-pcap', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const payload = await response.json()
        throw new Error(payload.detail?.message || 'Upload failed')
      }

      const data = await response.json()
      setAnalysis(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const severityData = analysis
    ? [
        { name: 'Critical', value: analysis.summary.severityCounts.critical },
        { name: 'High', value: analysis.summary.severityCounts.high },
        { name: 'Medium', value: analysis.summary.severityCounts.medium },
        { name: 'Low', value: analysis.summary.severityCounts.low },
      ]
    : []

  const httpsEventCount = analysis ? analysis.events.filter((event) => event.applicationProtocol === 'HTTPS').length : 0

  const COLORS = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']

  return (
    <div className="app-shell">
      <header className="hero-panel">
        <div>
          <h1>Deep Packet Analyzer Dashboard</h1>
          <p>Upload a PCAP for threat detection using the C++ DPI engine.</p>
        </div>
      </header>

      <section className="upload-panel">
        <div className="upload-card">
          <h2>Upload PCAP</h2>
          <input type="file" accept=".pcap" onChange={onFileChange} />
          <button disabled={!file || loading} onClick={uploadPcap}>
            {loading ? 'Analyzing...' : 'Analyze PCAP'}
          </button>
          {file && <p className="file-name">Selected: {file.name}</p>}
          {error && <p className="error-text">{error}</p>}
        </div>

        <div className="stat-cards">
          <div className="stat-card">
            <h3>Threats Found</h3>
            <p>{analysis ? analysis.summary.totalBlocked : 0}</p>
          </div>
          <div className="stat-card">
            <h3>Unique Threats</h3>
            <p>{analysis ? analysis.summary.uniqueThreats : 0}</p>
          </div>
          <div className="stat-card">
            <h3>HTTPS Events</h3>
            <p>{analysis ? analysis.summary.httpsCount : 0}</p>
          </div>
          <div className="stat-card">
            <h3>ML Alerts</h3>
            <p>{analysis ? (analysis.mlInsights?.modelLoaded ? analysis.mlInsights.suspiciousCount : 0) : 0}</p>
          </div>
          <div className="stat-card">
            <h3>AI Predictions</h3>
            <p>{analysis ? analysis.aiInsights?.predictions.length ?? 0 : 0}</p>
          </div>
          <div className="stat-card">
            <h3>Blocked Packets</h3>
            <p>{analysis ? analysis.summary.totalBlocked : 0}</p>
          </div>
        </div>
        <div className="severity-legend">
          <span className="legend-item critical">🔴 Critical</span>
          <span className="legend-item high">🟠 High</span>
          <span className="legend-item medium">🟡 Medium</span>
          <span className="legend-item low">🟢 Low</span>
        </div>
      </section>

      {analysis && (
        <section className="dashboard-grid">
          <div className="card large-card">
            <h2>Threat Table</h2>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>App</th>
                    <th>Host / SNI</th>
                    <th>Severity</th>
                    <th>Threats</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.events.map((event, index) => (
                    <tr key={index}>
                      <td>{event.timestamp}</td>
                      <td>{event.sourceIp}:{event.sourcePort}</td>
                      <td>{event.destinationIp}:{event.destinationPort}</td>
                      <td>{event.protocol}</td>
                      <td>{event.applicationProtocol || '-'}</td>
                      <td>{event.serverName || event.hostName || '-'}</td>
                      <td>{event.severity}</td>
                      <td>{event.reasons.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card chart-card">
            <h2>Threat Severity</h2>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" outerRadius={100} fill="#8884d8">
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="card chart-card">
            <h2>Threat Trend</h2>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={analysis.events.map((event, index) => ({
                name: event.timestamp,
                blocked: 1,
                threats: event.reasons.length,
              }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis />
                <Tooltip />
                <Area type="monotone" dataKey="threats" stroke="#1976d2" fill="#90caf9" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {analysis.aiInsights && (
            <div className="card large-card">
              <h2>AI Insights</h2>
              <div className="insight-section">
                <div>
                  <h3>Predictions</h3>
                  <ul>
                    {analysis.aiInsights.predictions.map((prediction, index) => (
                      <li key={index}>
                        <strong>{prediction.pattern}</strong> for <em>{prediction.value}</em> — {prediction.confidence}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3>Top Learned Patterns</h3>
                  <ol>
                    {analysis.aiInsights.topPatterns.map((pattern, index) => (
                      <li key={index}>
                        {pattern.type}: {pattern.value} ({pattern.count})
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>
          )}

          {analysis.mlInsights && (
            <div className="card large-card">
              <h2>ML Model Insights</h2>
              <div className="insight-section">
                <div>
                  <h3>Model Status</h3>
                  <p>{analysis.mlInsights.modelLoaded ? 'Loaded' : 'Not available'}</p>
                  <p>Suspicious packets: {analysis.mlInsights.suspiciousCount}</p>
                  <p>Average score: {analysis.mlInsights.averageScore.toFixed(2)}</p>
                </div>
                <div>
                  <h3>Top Suspicious Packets</h3>
                  <ol>
                    {analysis.mlInsights.topSuspicious.map((item, index) => (
                      <li key={index}>
                        Packet {item.packetIndex} score={item.score.toFixed(2)} pred={item.prediction} ports={item.srcPort} -&gt; {item.dstPort}
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

export default App
