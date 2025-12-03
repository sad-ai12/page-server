import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';

export default function Home() {
  const [username,setUsername]=useState('');
  const [password,setPassword]=useState('');
  const router=useRouter();

  const handleLogin=async()=>{
    try{
      const res=await axios.post('/api/auth',{action:'login',username,password});
      localStorage.setItem('token',res.data.token);
      router.push('/dashboard');
    }catch(err){
      alert(err.response.data.msg);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-96">
        <h1 className="text-xl font-bold mb-4">Login</h1>
        <input value={username} onChange={e=>setUsername(e.target.value)} placeholder="Username" className="w-full p-2 mb-4 border rounded"/>
        <input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" className="w-full p-2 mb-4 border rounded"/>
        <button onClick={handleLogin} className="w-full bg-blue-500 text-white p-2 rounded">Login</button>
      </div>
    </div>
  )
}
