import {
  BrainIcon,
  BriefcaseIcon,
  ClockCounterClockwiseIcon,
  DesktopTowerIcon,
  GearSixIcon,
  HeartbeatIcon,
  ShuffleIcon,
  SquaresFourIcon,
  WarningIcon,
  type Icon,
} from "@phosphor-icons/react";

export interface NavItem {
  href: string;
  label: string;
  icon: Icon;
  keywords?: string;
}

export const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: SquaresFourIcon, keywords: "dashboard home" },
  { href: "/alerts/", label: "Alerts", icon: WarningIcon, keywords: "detections incidents" },
  { href: "/flows/", label: "Flows", icon: ShuffleIcon, keywords: "connections traffic" },
  { href: "/hosts/", label: "Hosts", icon: DesktopTowerIcon, keywords: "ip devices" },
  {
    href: "/sessions/",
    label: "Sessions",
    icon: ClockCounterClockwiseIcon,
    keywords: "captures replays history",
  },
  { href: "/model/", label: "Model", icon: BrainIcon, keywords: "ml metrics threshold" },
  { href: "/jobs/", label: "Jobs", icon: BriefcaseIcon, keywords: "replay train upload pcap" },
  {
    href: "/system/",
    label: "System",
    icon: HeartbeatIcon,
    keywords: "health logs audit capabilities",
  },
  {
    href: "/settings/",
    label: "Settings",
    icon: GearSixIcon,
    keywords: "detection thresholds suppressions password",
  },
];

export function isActive(pathname: string, href: string): boolean {
  const normal = pathname.endsWith("/") ? pathname : `${pathname}/`;
  return href === "/" ? normal === "/" : normal.startsWith(href);
}
