from __future__ import annotations


VOICE_EXTENSION = r"""
<style>
#monVoiceToggle{margin-top:6px;border:1px solid #111;background:#fff;padding:4px 8px;font-size:8px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;cursor:pointer}#monVoiceToggle.on{background:#111;color:#fff}
</style>
<script>
(()=>{
const supported=('speechSynthesis' in window)&&('SpeechSynthesisUtterance' in window);let enabled=localStorage.getItem('monVoiceEnabled')==='1',seen=new Set(),lastWatchState='';
function speak(text){if(!supported||!enabled||!text)return;try{const u=new SpeechSynthesisUtterance(String(text));u.rate=1.02;u.pitch=0.92;u.volume=0.95;window.speechSynthesis.speak(u);}catch{}}
function install(){const state=document.querySelector('.headstate');if(!state||document.getElementById('monVoiceToggle'))return;const button=document.createElement('button');button.id='monVoiceToggle';button.textContent=supported?(enabled?'Voice On':'Voice Off'):'Voice Unsupported';button.disabled=!supported;button.classList.toggle('on',enabled);button.onclick=()=>{enabled=!enabled;localStorage.setItem('monVoiceEnabled',enabled?'1':'0');button.textContent=enabled?'Voice On':'Voice Off';button.classList.toggle('on',enabled);if(enabled)speak('MON voice alerts enabled.');else window.speechSynthesis.cancel();};state.appendChild(button);}
function eventKey(item){return [item.kind||'',item.severity||'',item.title||'',item.timestamp||''].join('|')}
async function poll(){if(!enabled)return;try{const response=await fetch('/api/v1/system/watchdog',{cache:'no-store'});if(!response.ok)return;const data=await response.json();const state=String(data.state||'UNKNOWN').toUpperCase();if(lastWatchState&&state!==lastWatchState&&state!=='HEALTHY')speak(`MON watchdog reports ${state}. Open the System page for cause and fix.`);if(lastWatchState&&state==='HEALTHY'&&lastWatchState!=='HEALTHY')speak('MON watchdog reports the runtime is healthy again.');lastWatchState=state;for(const item of data.anomalies?.top||[]){const severity=String(item.severity||'INFO').toUpperCase();if(!['HIGH','CRITICAL'].includes(severity))continue;const key=eventKey(item);if(seen.has(key))continue;seen.add(key);if(seen.size>200)seen=new Set([...seen].slice(-120));speak(`${severity} security alert. ${item.title||'Packet derived anomaly detected.'}`);}}catch{}}
install();setInterval(poll,3500);setTimeout(poll,1500);
})();
</script>
"""
