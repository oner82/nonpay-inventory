// 엑셀은 기기 안에서만 읽고 처방에 필요한 열만 기존 해석기로 전달한다.
(() => {
  let loading;
  const load = () => {
    if(window.XLSX) return Promise.resolve(window.XLSX);
    if(!loading) loading=new Promise((resolve,reject)=>{
      const script=document.createElement('script');script.src='./vendor/xlsx.full.min.js?v=0.20.3';
      script.onload=()=>resolve(window.XLSX);script.onerror=()=>{loading=null;script.remove();reject(Error('엑셀 읽기 도구를 불러오지 못했습니다. 다시 시도해 주세요.'));};document.head.appendChild(script);
    });
    return loading;
  };
  const read = async file => {
    if(!/\.xlsx$/i.test(file.name)||file.size>5*1024*1024)throw Error('5MB 이하의 .xlsx 파일을 선택해 주세요.');
    const XLSX=await load();
    const book=XLSX.read(await file.arrayBuffer(),{type:'array',sheetRows:202,cellFormula:true});
    if(!book.SheetNames.length||book.SheetNames.length>30)throw Error('시트 수를 확인해 주세요. 한 케이스씩 불러오세요.');
    return book;
  };
  const parseSheet = (book,name) => {
    const X=window.XLSX,sheet=book.Sheets[name];if(!sheet||!sheet['!ref'])throw Error('빈 시트입니다.');
    const range=X.utils.decode_range(sheet['!fullref']||sheet['!ref']);
    if(range.e.r>=201||range.e.c>=150)throw Error('한 시트에 한 케이스, 최대 200행의 처방을 넣어 주세요.');
    const width=range.e.c+1;
    if(![84,103].includes(width))throw Error(`지원하지 않는 엑셀 열 구조(${width}열)입니다. OCS에서 전체 처방 열을 복사해 주세요.`);
    const data=X.utils.sheet_to_json(sheet,{header:1,defval:'',raw:true,range:0});
    const lines=[];
    data.forEach((row,index)=>{
      const c=Array.from({length:width},(_,i)=>String(row[i]??''));
      if(c.every(v=>!v.trim()))return;
      const fields=width===84?[0,2,3,5,6,7]:[0,1,3,4,7,8,9,14];
      if(fields.some(col=>sheet[X.utils.encode_cell({r:index,c:col})]?.f))throw Error(`${index+1}행에 수식이 있습니다. 처방 값을 그대로 복사해 주세요.`);
      if(width===103){lines.push(c.join('\t'));return;}
      const defaults={5:'1',6:'1',7:'1',9:'N',22:'C1'};
      if(c.every((v,i)=>v.trim()===(defaults[i]||'')))return;
      // 84열 표에는 텍스트 복사의 A 표식과 보조 열이 없으므로 명시적으로 대응한다.
      if([c[0],c[2],c[3]].some(v=>/[\t\r\n]/.test(v)))throw Error(`${index+1}행의 상태·코드·명칭에 줄바꿈이 있습니다.`);
      const out=Array(103).fill('');Object.assign(out,{0:'A',1:c[0],3:c[2],4:c[3],7:c[5],8:c[6],9:c[7]});
      // 취소 표시가 포함된 명칭만 삭제로 판정한다. 글자색만으로 추측하지 않는다.
      out[14]=/^\s*D\/C:1\]/.test(c[3])?'D':'';
      lines.push(out.join('\t'));
    });
    return window.OROcs.parse(lines.join('\n'));
  };
  window.OROcsExcel={read,parseSheet};
})();
