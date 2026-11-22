set(native_dir "${CMAKE_CURRENT_LIST_DIR}")
set(unit_dir "lib/systemd/system" CACHE STRING "systemd system unit installation directory")
foreach(unit vpnctl.socket vpnctl-autolaunch.service vpnctl@.service vpnctl-routing.service vpnctl-session.service
             vpnctl-tunnel.service vpnctl-refresh.service vpnctl-refresh.timer vpnctl-dns.service)
  configure_file("${native_dir}/systemd/${unit}.in" "${CMAKE_CURRENT_BINARY_DIR}/${unit}" @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${unit}" DESTINATION "${unit_dir}")
endforeach()
configure_file("${native_dir}/network.py.in" "${CMAKE_CURRENT_BINARY_DIR}/vpnctl-network" @ONLY)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/vpnctl-network" DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}")
install(FILES "${native_dir}/sysusers.conf" DESTINATION lib/sysusers.d RENAME vpnctl.conf)
install(FILES "${native_dir}/tmpfiles.conf" DESTINATION lib/tmpfiles.d RENAME vpnctl.conf)
install(FILES "${native_dir}/policy.example.json" "${native_dir}/routing.nft.in"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/vpnctl")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/vpnctl")
