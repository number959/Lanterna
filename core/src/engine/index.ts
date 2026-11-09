export * from './types';
export { analyze, ENGINE_VERSION, CATEGORY_LABELS, corporateDomain, primaryAdapter } from './analyze';
export type { CorporateDomain } from './analyze';
export { METRICS, METRIC_LIST } from './kb/metrics';
export { ACTIONS } from './kb/actions';
export { asStep, DRIVER_PLACEHOLDER, stepCmd, stepLine, stepOpens, stepsFor, stepsText, stepText, stepVars, windowsMajor } from './steps';
export type { StepVars, WinMajor } from './steps';
export { ASSESS_AREAS, ASSESS_QUESTIONS, scoreAssessment } from './kb/assessment';
export type { AreaScore, AssessArea, AssessAreaId, AssessQuestion } from './kb/assessment';
export { adviseChannels, apCount, bandOf, freqToChannel, channelToFreq, ownRadios, secFamily, spectrum, phyLabel } from './wifi';
export { renderText } from './report';
export {
  analyzeCerts,
  CERT_CRIT_DAYS,
  CERT_MAX_TARGETS,
  CERT_TRUST_TEXT,
  CERT_WARN_DAYS,
  certExpiry,
  certExpiryText,
  certFailHint,
  certIssuer,
  certIssues,
  certNormalize,
  certSeverity,
  certSummary,
  certTarget,
  certTrustShort,
  certValue,
  certWarnDays,
  certWhere,
} from './certs';
export type { CertExpiry, CertIssue } from './certs';
export {
  analyzeCrashes,
  BUGCHECKS_MORE,
  bugcheckInfo,
  bugcheckText,
  CRASH_DUMP_TYPE,
  CRASH_FAMILY_TEXT,
  CRASH_LIMITED,
  CRASH_RECENT_DAYS,
  CRASH_REPEAT,
  crashCode,
  crashCodes,
  crashDrivers,
  crashFolderText,
  crashRead,
  crashSetting,
  crashSummary,
  crashWhen,
  culpritHow,
  lastBugcheckEvent,
  noCulpritText,
  parseBugcheckEvent,
} from './crash';
export type { BugcheckInfo, CrashFamily, CrashGroup } from './crash';
export {
  analyzeDevices,
  DEVICE_PROBLEMS,
  deviceClassText,
  deviceOfDriver,
  deviceProblemDetail,
  deviceProblemText,
  deviceSeverity,
  driverText,
  isDisabled,
  isTransient,
  oldDrivers,
  symbolicDate,
  thirdPartyDrivers,
} from './devices';
export type { DriverPackage } from './devices';
export {
  analyzeStability,
  appHint,
  APP_CRIT,
  APPS_WARN,
  BOOT_CRIT_MS,
  BOOT_WARN_MS,
  bootSample,
  bootSeverity,
  bootTypical,
  EXCEPTION_TEXT,
  failText,
  FIRMWARE_INFO_MS,
  FIRMWARE_WARN_MS,
  msText,
  reliabilityFalling,
  reliabilitySeverity,
  SHUTDOWN_INFO_MS,
  SHUTDOWN_WARN_MS,
  SLOW_KIND,
} from './boot';
export { analyzeMaint, failedUpdates, memDiagPending, WU_ERRORS, wuErrorText, wuGroup } from './maint';
export type { WuErrorGroup } from './maint';
export { analyzeProtection, ENC_METHOD, ENC_PROTECTOR, encText, isPortable } from './protect';
export { analyzePrinting, isRealPrinter, PRINTER_FLAG, printerProblems, printerText } from './printing';
export {
  analyzeUsb,
  USB_CONTROLLER,
  USB_KIND,
  USB_SPEED,
  USB_STATUS,
  USB_VENDORS,
  usbDeviceLabel,
  usbDevices,
  usbNodes,
  usbPortProblems,
  usbSlow,
  usbSlowReason,
  usbSpeedText,
  usbWhere,
} from './usb';
export type { UsbNode } from './usb';
export {
  analyzeSurvey,
  bandText,
  dbmText,
  dipSeverity,
  gatewayText,
  pingAnswerers,
  pingMeasured,
  radioText,
  roomKey,
  routerSilent,
  roomSlug,
  roomValue,
  rssiMeaning,
  rssiSeverity,
  rssiWord,
  sampleIssues,
  sampleSeverity,
  surveyAliases,
  surveyForExport,
  surveyRooms,
  worstSample,
  SURVEY_CRIT_DBM,
  SURVEY_GREAT_DBM,
  SURVEY_INFO_DBM,
  SURVEY_JITTER_CRIT,
  SURVEY_JITTER_WARN,
  SURVEY_LOSS_CRIT,
  SURVEY_LOSS_WARN,
  SURVEY_MAX_ROOM,
  SURVEY_OK_DBM,
  SURVEY_RTT_CRIT,
  SURVEY_RTT_WARN,
  SURVEY_SECONDS,
  SURVEY_SPREAD_DB,
  SURVEY_STICKY_DB,
  SURVEY_STRONG_DBM,
  SURVEY_UTIL_WARN,
} from './survey';
export type { RoomResult, SurveyAliases, SurveyIssue } from './survey';
export {
  analyzeSpeed,
  BLOAT_LABEL,
  bloatSeverity,
  bloatValue,
  dirBloat,
  mbpsText,
  probeWait,
  SPEED_BLOAT_CRIT_MS,
  SPEED_BLOAT_WARN_MS,
  SPEED_FAST_MBPS,
  SPEED_LEGAL_NOTE,
  SPEED_LOST_NOTE_PCT,
  SPEED_PROBE_TIMEOUT_MS,
  SPEED_RETRANS_INFO_PCT,
  speedBloat,
  speedBytes,
  speedCaveats,
  speedCity,
  speedDocRows,
  speedErr,
  speedLoadedText,
  speedMs,
  speedTextLines,
  speedValue,
  speedWhere,
  waitLabel,
} from './speedtest';
export type { DirBloat, SpeedBloat } from './speedtest';
export { documentParts, renderDocument } from './document';
export type { DocOptions } from './document';
export { BUGCHECKS, dateIt, lastQualityUpdate, ramTestSeverity, WIN10_EOS, WIN10_ESU_CONSUMER, WIN11_EOS } from './pc';
export { attrState, bytesText, diskStatus, isFlashDisk, smartId, smartName, smartRaw, STATUS_LABEL } from './smart';
export type { AttrState, DiskSignal, DiskStatus } from './smart';
export { cacheText, channelMode, channelOf, coreLayout, cpuVendor, memVendor, moduleText } from './hardware';
export type { ChannelMode } from './hardware';
export { pctText, reclaimableBytes, sizeText, spaceHintLabel, spaceLine, SPACE_CATEGORY_LABEL, SPACE_HINTS, SPACE_RISK_LABEL, unattributedBytes } from './space';
export type { SpaceHintInfo, SpaceRisk } from './space';
export { THREAT_SEVERITY, THREAT_STATUS, unresolved as unresolvedThreat } from './defender';
