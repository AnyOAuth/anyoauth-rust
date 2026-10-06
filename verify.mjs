// Generated standalone SDK checks. Canonical source: AnyOAuth/anyoauth.
import {spawn} from 'node:child_process';
for(const command of [["cargo","build","--locked","--bin","conformance"],["node","test/conformance/check.mjs"]]){
  console.log('> '+command.join(' '));
  await new Promise((resolve,reject)=>{const child=spawn(command[0],command.slice(1),{stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(new Error(command[0]+' failed: '+code)));});
}
