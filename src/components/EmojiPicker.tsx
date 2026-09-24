import {useMemo,useState} from 'react';
const groups:{label:string;emoji:string[];icon:string}[]=[
 {label:'Смайлы',icon:'☺',emoji:['😀','😃','😄','😁','😆','😅','😂','🤣','😊','😇','🙂','🙃','😉','😌','😍','🥰','😘','😗','😙','😚','😋','😛','😝','😜','🤪','🤨','🧐','🤓','😎','🥳','🤩']},
 {label:'Эмоции',icon:'✨',emoji:['😭','😢','😥','😰','😅','😡','🤬','😱','😳','🤯','😴','🤔','🤗','🫡','🙄','😬','😮','😲','🥺','😤','😈','👿','💀','☠️','👻','👽']},
 {label:'Жесты',icon:'✌',emoji:['👋','🤚','🖐️','✋','🖖','👌','🤏','✌️','🤞','🤟','🤘','🤙','👈','👉','👆','👇','☝️','👍','👎','✊','👏','🙌','🫶','🙏']},
 {label:'Животные',icon:'🐻',emoji:['🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🙈','🐔','🐧','🐦','🦄','🐝','🦋','🐌','🐞','🐠']},
 {label:'Еда',icon:'🍔',emoji:['🍏','🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍒','🥝','🍕','🍔','🍟','🌭','🍿','🍩','🍪','🎂','🍰','☕','🧋','🍺']},
 {label:'Символы',icon:'❤️',emoji:['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💟','✅','❌','⚡','🔥','⭐']}
];
export function EmojiPicker({onPick}:{onPick:(emoji:string)=>void}){const [tab,setTab]=useState(0);const [query,setQuery]=useState('');const emojis=useMemo(()=>query?groups.flatMap(g=>g.emoji).filter(e=>e.includes(query)):groups[tab].emoji,[query,tab]);return <div className="emoji-popover"><input className="emoji-search" placeholder="Поиск emoji" value={query} onChange={e=>setQuery(e.target.value)}/><div className="emoji-tabs">{groups.map((g,i)=><button key={g.label} className={tab===i&&!query?'active':''} onClick={()=>{setTab(i);setQuery('')}} title={g.label}>{g.icon}</button>)}</div><div className="emoji-grid">{emojis.map((e,i)=><button key={`${e}-${i}`} onClick={()=>onPick(e)}>{e}</button>)}</div></div>}
