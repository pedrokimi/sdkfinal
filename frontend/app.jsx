const { useEffect, useState } = React

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const sdk = window.IdentitySDK.initIdentitySdk({ baseUrl: 'http://localhost:4001', endpoint: '/identity/verify', biometric: { enabled: true } })
    setLoading(true)
    sdk.verify().then((r) => setResult({ data: r, sdk })).finally(() => setLoading(false))
  }, [])

  return (
    <div style={{ maxWidth: 720, margin: '0 auto' }}>
      <h1>NexShop Identity SDK</h1>
      <p>Exemplo de integracao do SDK (coleta passiva e chamada ao backend).</p>
      {loading && <p>Avaliando...</p>}
      {!loading && result && (
        <>
          <pre>{JSON.stringify(result.data, null, 2)}</pre>
          {result.data && result.data.challengeRequired && (
            <div style={{ marginTop: 16 }}>
              <h3>Desafio sugerido: {result.data.suggestedChallenge}</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button onClick={async () => {
                  const out = await result.sdk.initiateChallenge({ type: 'OTP', userLabel: 'DemoUser' })
                  alert('OTP iniciado. ID: ' + out.challengeId)
                  const code = prompt('Digite o codigo OTP:')
                  if (code) {
                    const v = await result.sdk.verifyChallenge({ type: 'OTP', challengeId: out.challengeId, code })
                    alert(JSON.stringify(v))
                  }
                }}>Usar OTP</button>
                <button onClick={async () => {
                  const email = prompt('Email para receber o codigo:')
                  if (!email) return
                  const out = await result.sdk.initiateChallenge({ type: 'EMAIL', email })
                  const code = prompt('Digite o codigo recebido por email:')
                  if (code) {
                    const v = await result.sdk.verifyChallenge({ type: 'EMAIL', challengeId: out.challengeId, code })
                    alert(JSON.stringify(v))
                  }
                }}>Usar Email</button>
                <button onClick={async () => {
                  await result.sdk.ensureBiometryModels()
                  const stream = await navigator.mediaDevices.getUserMedia({ video: true })
                  const video = document.createElement('video')
                  video.autoplay = true
                  video.srcObject = stream
                  const w = window.open('')
                  if (w) w.document.body.appendChild(video)
                  setTimeout(async () => {
                    const embedding = await result.sdk.captureFaceEmbedding(video)
                    stream.getTracks().forEach(t => t.stop())
                    if (w) w.close()
                    if (!embedding) return alert('Nenhum rosto detectado')
                    const init = await result.sdk.initiateChallenge({ type: 'BIOMETRIC', referenceEmbedding: embedding })
                    alert('Biometria iniciada. ID: ' + init.challengeId)
                    const stream2 = await navigator.mediaDevices.getUserMedia({ video: true })
                    const video2 = document.createElement('video')
                    video2.autoplay = true
                    video2.srcObject = stream2
                    const w2 = window.open('')
                    if (w2) w2.document.body.appendChild(video2)
                    setTimeout(async () => {
                      const embedding2 = await result.sdk.captureFaceEmbedding(video2)
                      stream2.getTracks().forEach(t => t.stop())
                      if (w2) w2.close()
                      if (!embedding2) return alert('Nenhum rosto detectado na verificacao')
                      const v = await result.sdk.verifyChallenge({ type: 'BIOMETRIC', challengeId: init.challengeId, embedding: embedding2 })
                      alert(JSON.stringify(v))
                    }, 1500)
                  }, 1500)
                }}>Usar Biometria</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />)


