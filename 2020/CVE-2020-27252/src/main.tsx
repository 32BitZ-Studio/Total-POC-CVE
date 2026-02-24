import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './Layout'
import { Description, HackSim, Home, Impact, VulnDescription } from './App'
import { ChakraProvider } from '@chakra-ui/react'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

function App() {
  return (
    <ChakraProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Home />} />
            <Route path="/description" element={<Description />} />
            <Route path="/vuln" element={<VulnDescription />} />
            <Route path='/hack-sim' element={<HackSim />} />
            <Route path='/impact' element={<Impact />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ChakraProvider>
  )
}
