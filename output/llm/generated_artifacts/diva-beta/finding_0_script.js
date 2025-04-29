// Frida script for finding_0
setImmediate(function() {
    Java.perform(function() {
        console.log('[*] Starting Frida script for finding_0...');
        try {
             const targetClass = Java.use('jakhar.aseem.diva.InsecureDataStorage1Activity');
             const targetMethod = targetClass.saveCredentials;
             targetMethod.implementation = function(view) { // Added 'view' argument based on method signature
                  console.log('[*] <jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)> Hooked!');
                  try {
                      // Call the original method
                      var result = targetMethod.apply(this, arguments);
                      // NOTE: For SharedPreferences write, confirmation might not involve an exception.
                      // This log will only trigger if the original method *throws* an exception.
                      // Consider adding a non-exception-based log if confirmation means simply "write occurred".
                      // Example: console.log("[FRIDA_VULN_CONFIRMED] finding_finding_0 | Strategy: VerifySharedPrefWrite | Detail: Method executed successfully, attempting SharedPreferences write.");
                      return result;
                  } catch (e) {
                      // Log confirmation *only* if an exception occurs during the method call
                      console.log('[FRIDA_VULN_CONFIRMED] finding_finding_0 | Strategy: VerifySharedPrefWrite | Detail: Exception caught during saveCredentials: ' + e.message);
                      throw e; // Re-throw the exception to maintain original behavior
                  }
             };
        } catch(err) { console.error('[!] Error hooking <jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)>: ' + err.message); }
        console.log('[*] Frida hooks installed.');
    });
});