// Fast JSON field extractor for hooks
// Usage: node parse-input.js field1 field2 ...
// Reads JSON from stdin, outputs fields separated by \n
let d='';
process.stdin.on('data',c=>d+=c);
process.stdin.on('end',()=>{
  try{
    const j=JSON.parse(d);
    const fields=process.argv.slice(2);
    for(const f of fields){
      const val=f.split('.').reduce((o,k)=>o?.[k],j)||'';
      process.stdout.write(val+'\n');
    }
  }catch{
    process.stdout.write('\n'.repeat(process.argv.length-2));
  }
});
