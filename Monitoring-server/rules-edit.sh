#Bu prometheus.yml dosyasına eklenmesi gereken bir örnek uyarı kuralıdır. Bu kural, CPU kullanımının belirli bir eşiği aştığında bir uyarı oluşturur.

#enellikle, Prometheus'un yapılandırma dosyasındaki rule_files bölümüne eklenir. Bu bölüm, Prometheus'un izleyeceği ek bir kural dosyasını tanımlar.

rule_files:
  - "alert.rules.yml"

#Bu şekilde ayarlama yaparak  alert.rules.yml doğrultusunda bağlanır.
#Bu dosyayı Prometheus'un yapılandırma dosyasının olduğu dizine kaydedin ve ardından Prometheus'u yeniden başlatın veya yeniden yükleyin. Bu şekilde, yeni uyarı kuralı Prometheus tarafından izlenmeye başlanacaktır.






