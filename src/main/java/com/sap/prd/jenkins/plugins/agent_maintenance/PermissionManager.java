package com.sap.prd.jenkins.plugins.agent_maintenance;

import hudson.model.Computer;
import hudson.security.AccessDeniedException3;
import hudson.security.Permission;
import jenkins.model.Jenkins;

/**
 * Centralized permission manager for maintenance targets.
 * <p>
 * Permission rules:
 * <ul>
 *   <li>AGENT view: Computer.EXTENDED_READ | Computer.CONFIGURE | Computer.DISCONNECT</li>
 *   <li>AGENT modify/delete: Computer.CONFIGURE | Computer.DISCONNECT</li>
 *   <li>CLOUD view: Jenkins.SYSTEM_READ | Jenkins.ADMINISTER</li>
 *   <li>CLOUD modify/delete: Jenkins.ADMINISTER only</li>
 * </ul>
 */
public final class PermissionManager {

  private PermissionManager() {}

  /**
   * Returns true if the current user can VIEW maintenance windows for this target.
   */
  public static boolean canView(MaintenanceTarget target) {
    return switch (target.getType()) {
      case AGENT -> {
        Computer c = getComputer(target);
        yield c != null
            && (c.hasPermission(Computer.EXTENDED_READ)
                || c.hasPermission(Computer.CONFIGURE)
                || c.hasPermission(Computer.DISCONNECT));
      }
      case CLOUD -> Jenkins.get().hasPermission(Jenkins.SYSTEM_READ);
    };
  }

  /**
   * Returns true if the current user can ADD or EDIT maintenance windows for this target.
   */
  public static boolean canModify(MaintenanceTarget target) {
    return switch (target.getType()) {
      case AGENT -> {
        Computer c = getComputer(target);
        yield c != null
            && (c.hasPermission(Computer.CONFIGURE)
                || c.hasPermission(Computer.DISCONNECT));
      }
      case CLOUD -> Jenkins.get().hasPermission(Jenkins.ADMINISTER);
    };
  }

  /**
   * Returns true if the current user can DELETE maintenance windows for this target.
   */
  public static boolean canDelete(MaintenanceTarget target) {
    return canModify(target); // same threshold for now
  }

  /**
   * Throws AccessDeniedException if the user cannot VIEW.
   */
  public static void checkCanView(MaintenanceTarget target) {
    if (!canView(target)) {
      throwDenied(target.getType() == MaintenanceTarget.TargetType.CLOUD
          ? Jenkins.SYSTEM_READ
          : Computer.EXTENDED_READ);
    }
  }

  /**
   * Throws AccessDeniedException if the user cannot MODIFY.
   */
  public static void checkCanModify(MaintenanceTarget target) {
    if (!canModify(target)) {
      throwDenied(target.getType() == MaintenanceTarget.TargetType.CLOUD
          ? Jenkins.ADMINISTER
          : Computer.CONFIGURE);
    }
  }

  /**
   * Throws AccessDeniedException if the user cannot DELETE.
   */
  public static void checkCanDelete(MaintenanceTarget target) {
    if (!canDelete(target)) {
      throwDenied(target.getType() == MaintenanceTarget.TargetType.CLOUD
          ? Jenkins.ADMINISTER
          : Computer.CONFIGURE);
    }
  }

  private static Computer getComputer(MaintenanceTarget target) {
    return Jenkins.get().getComputer(target.getName());
  }

  private static void throwDenied(Permission required) {
    throw new AccessDeniedException3(Jenkins.getAuthentication2(), required);
  }
}
