// Frida script for finding_5
setImmediate(function() {
    Java.perform(function() {
        console.log('[*] Starting Frida script for finding_5...');
        try {
             const targetClass = Java.use('jakhar.aseem.diva.InsecureDataStorage3Activity');
             const targetMethod = targetClass.saveCredentials;
             targetMethod.implementation = function(view) { // Explicitly declare the 'view' argument based on method signature
                  console.log('[*] <jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)> Hooked!');
                  try {
                      // Call the original method with the correct arguments
                      var result = targetMethod.call(this, view);
                      return result;
                  } catch (e) {
                      // VULNERABILITY CONFIRMED: Log the specific confirmation message
                      console.log("[FRIDA_VULN_CONFIRMED] finding_finding_5 | Strategy: FuzzFileWriteException | Detail: Exception caught during file write operation: " + e.message);
                      // Re-throw the exception to allow normal error handling if needed, or just return
                      throw e; // Or consider just returning if crashing the app is undesirable
                  }
             };
        } catch(err) { console.error('[!] Error hooking <jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)>: ' + err.message); }
        console.log('[*] Frida hooks installed.');
    });
});