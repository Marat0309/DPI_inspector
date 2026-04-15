#!/usr/bin/env bash

# Localized labels used by high-level UI output.
t() {
  local key="$1"
  if [ "$LANG_MODE" = "ru" ]; then
    case "$key" in
      reachability) echo "Доступность" ;;
      camouflage) echo "Маскировка" ;;
      exposure) echo "Экспозиция" ;;
      confidence) echo "Уверенность" ;;
      protocol_hypotheses) echo "Гипотезы протоколов" ;;
      overall_assessment) echo "Общая оценка" ;;
      surface_risk) echo "Риск поверхности" ;;
      hardening_hints) echo "Рекомендации по защите" ;;
      tls_surface_class) echo "Класс TLS-поверхности" ;;
      cert_routing_profile) echo "Профиль маршрутизации сертификата" ;;
      *) echo "$key" ;;
    esac
  else
    case "$key" in
      reachability) echo "Reachability" ;;
      camouflage) echo "Camouflage" ;;
      exposure) echo "Exposure" ;;
      confidence) echo "Confidence" ;;
      protocol_hypotheses) echo "Protocol hypotheses" ;;
      overall_assessment) echo "Overall assessment" ;;
      surface_risk) echo "Surface risk" ;;
      hardening_hints) echo "Hardening hints" ;;
      tls_surface_class) echo "TLS surface class" ;;
      cert_routing_profile) echo "Cert routing profile" ;;
      *) echo "$key" ;;
    esac
  fi
}
