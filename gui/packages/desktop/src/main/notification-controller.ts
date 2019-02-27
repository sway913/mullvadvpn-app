import { app, nativeImage, NativeImage, Notification, shell } from 'electron';
import path from 'path';
import config from '../config.json';

import { TunnelStateTransition } from '../shared/daemon-rpc-types';

export default class NotificationController {
  private lastTunnelStateAnnouncement?: { body: string; notification: Notification };
  private reconnecting = false;
  private presentedNotifications: { [key: string]: boolean } = {};
  private pendingNotifications: Notification[] = [];
  private notificationTitle = process.platform === 'linux' ? app.getName() : '';
  private notificationIcon?: NativeImage;

  constructor() {
    if (process.platform === 'linux') {
      const basePath = path.resolve(path.join(__dirname, '../../assets/images'));
      this.notificationIcon = nativeImage.createFromPath(
        path.join(basePath, 'icon-notification.png'),
      );
    }
  }

  public notifyTunnelState(tunnelState: TunnelStateTransition) {
    switch (tunnelState.state) {
      case 'connecting':
        if (!this.reconnecting) {
          this.showTunnelStateNotification('Connecting');
        }
        break;
      case 'connected':
        this.showTunnelStateNotification('Secured');
        break;
      case 'disconnected':
        this.showTunnelStateNotification('Unsecured');
        break;
      case 'blocked':
        switch (tunnelState.details.reason) {
          case 'set_firewall_policy_error':
            this.showTunnelStateNotification('Critical failure - Unsecured');
            break;
          default:
            this.showTunnelStateNotification('Blocked all connections');
            break;
        }
        break;
      case 'disconnecting':
        switch (tunnelState.details) {
          case 'nothing':
          case 'block':
            // no-op
            break;
          case 'reconnect':
            this.showTunnelStateNotification('Reconnecting');
            this.reconnecting = true;
            return;
        }
        break;
    }

    this.reconnecting = false;
  }

  public notifyInconsistentVersion() {
    this.presentNotificationOnce('inconsistent-version', () => {
      const notification = new Notification({
        title: this.notificationTitle,
        body: 'Inconsistent internal version information, please restart the app',
        silent: true,
        icon: this.notificationIcon,
      });
      this.scheduleNotification(notification);
    });
  }

  public notifyUnsupportedVersion(upgradeVersion: string) {
    this.presentNotificationOnce('unsupported-version', () => {
      const notification = new Notification({
        title: this.notificationTitle,
        body: `You are running an unsupported app version. Please upgrade to ${upgradeVersion} now to ensure your security`,
        silent: true,
        icon: this.notificationIcon,
      });

      notification.on('click', () => {
        shell.openExternal(config.links.download);
      });

      this.scheduleNotification(notification);
    });
  }

  public cancelPendingNotifications() {
    for (const notification of this.pendingNotifications) {
      notification.close();
    }
  }

  private showTunnelStateNotification(message: string) {
    const lastAnnouncement = this.lastTunnelStateAnnouncement;
    const sameAsLastNotification = lastAnnouncement && lastAnnouncement.body === message;

    if (sameAsLastNotification) {
      return;
    }

    const newNotification = new Notification({
      title: this.notificationTitle,
      body: message,
      silent: true,
      icon: this.notificationIcon,
    });

    if (lastAnnouncement) {
      lastAnnouncement.notification.close();
    }

    this.lastTunnelStateAnnouncement = {
      body: message,
      notification: newNotification,
    };

    this.scheduleNotification(newNotification);
  }

  private presentNotificationOnce(notificationName: string, presentNotification: () => void) {
    const presented = this.presentedNotifications;
    if (!presented[notificationName]) {
      presented[notificationName] = true;
      presentNotification();
    }
  }

  private scheduleNotification(notification: Notification) {
    this.addPendingNotification(notification);

    notification.show();

    setTimeout(() => notification.close(), 4000);
  }

  private addPendingNotification(notification: Notification) {
    notification.on('close', () => {
      this.removePendingNotification(notification);
    });

    this.pendingNotifications.push(notification);
  }

  private removePendingNotification(notification: Notification) {
    const index = this.pendingNotifications.indexOf(notification);
    if (index !== -1) {
      this.pendingNotifications.splice(index, 1);
    }
  }
}