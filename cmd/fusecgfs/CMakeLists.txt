add_executable(cgrpfs cgrpfs.c cgrpfs_vnops.c)
target_link_libraries(cgrpfs PkgConfig::fuse ${KQ_LIBS} initware-shared)