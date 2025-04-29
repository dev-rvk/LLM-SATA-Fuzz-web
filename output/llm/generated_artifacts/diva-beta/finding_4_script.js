// Frida script for finding_4
setImmediate(function() {
    Java.perform(function() {
        console.log('[*] Starting Frida script for finding_4...');
        try {
             const targetClass = Java.use('jakhar.aseem.diva.InsecureDataStorage3Activity');
             const targetMethod = targetClass.saveCredentials;
             targetMethod.implementation = function(/* args */) {
                  console.log('[*] <jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)> Hooked!');
                  try {
                      var result = targetMethod.apply(this, arguments);
                      return result;
                  } catch (e) {
                      console.log('[FRIDA_VULN_CONFIRMED] finding_finding_4 | Strategy: FuzzFileWriteException | Detail: Exception caught: ' + e.message);
                      throw e;
                  }
             };
        } catch(err) { console.error('[!] Error hooking <jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)>: ' + err.message); }
        console.log('[*] Frida hooks installed.');
    });
});