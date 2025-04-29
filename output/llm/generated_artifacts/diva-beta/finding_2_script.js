// Frida script for finding_2
setImmediate(function() {
    Java.perform(function() {
        console.log('[*] Starting Frida script for finding_2...');
        try {
             const targetClass = Java.use('jakhar.aseem.diva.LogActivity');
             const targetMethod = targetClass.checkout;
             targetMethod.implementation = function(/* args */) {
                  console.log('[*] <jakhar.aseem.diva.LogActivity: void checkout(android.view.View)> Hooked!');
                  try {
                      var result = targetMethod.apply(this, arguments);
                      return result;
                  } catch (e) {
                      console.log('[FRIDA_VULN_CONFIRMED] finding_finding_2 | Strategy: VerifyLogContent | Detail: Exception caught: ' + e.message);
                      throw e;
                  }
             };
        } catch(err) { console.error('[!] Error hooking <jakhar.aseem.diva.LogActivity: void checkout(android.view.View)>: ' + err.message); }
        console.log('[*] Frida hooks installed.');
    });
});