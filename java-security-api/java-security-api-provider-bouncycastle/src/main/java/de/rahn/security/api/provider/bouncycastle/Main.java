package de.rahn.security.api.provider.bouncycastle;

import de.rahn.security.api.SecurityPrinter;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** @author Frank W. Rahn */
public class Main extends SecurityPrinter {

  public static void main(String[] args) {
    try (Main main = new Main()) {
      main.run();
    }
  }

  @Override
  public void run() {
    appendTitle("Die Liste der Security-Provider von The Legion of Bouncy Castle");

    for (Provider provider : Security.getProviders()) {
      Security.removeProvider(provider.getName());
    }

    Security.addProvider(new BouncyCastleProvider());

    for (Provider provider : Security.getProviders()) {
      appendDesc("Security Provider Info")
          .appendValue("Name", provider.getName())
          .appendValue("Version", provider.getVersionStr())
          .appendValue("Info", provider.getInfo())
          .appendValue("Classname", provider.getClass().getName())
          .appendToString(provider);

      Map<String, List<String>> types = new HashMap<>();
      for (Provider.Service service : provider.getServices()) {
        if (!types.containsKey(service.getType())) {
          types.put(service.getType(), new ArrayList<>());
        }
        types.get(service.getType()).add(service.getAlgorithm());
      }

      String[] keys = types.keySet().toArray(new String[0]);
      Arrays.sort(keys);

      for (String type : keys) {
        appendValue("Service - " + type, 40, types.get(type));
      }

      resetWidth().appendln();
    }
  }
}
