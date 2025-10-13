import React, { useEffect, useState } from 'react'
const KEY = 'app_payments_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function PaymentsManager() {
  const [list, setList] = useState([])

  useEffect(() => setList(read()), [])

  function exportCSV() {
    const rows = list.map(p => `${p.id},${p.invoiceNo},${p.instituteName},${p.amount},${p.date}`)
    const csv = ['ID,Invoice,Institute,Amount,Date', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'payments.csv'; a.click(); URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Payments & Invoices</h3>

      <div style={{ marginBottom: 12 }}>
        <button onClick={exportCSV} style={{ padding: '8px 12px' }}>Export CSV</button>
      </div>

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No payments recorded.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
              <th style={{ padding: 8 }}>Invoice</th><th>Institute</th><th>Amount</th><th>Date</th><th>Action</th>
            </tr>
          </thead>
          <tbody>
            {list.map(p => (
              <tr key={p.id}>
                <td style={{ padding: 8 }}>{p.invoiceNo}</td>
                <td>{p.instituteName}</td>
                <td>{p.amount}</td>
                <td>{p.date}</td>
                <td><button onClick={() => window.alert(JSON.stringify(p, null, 2))}>View</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
