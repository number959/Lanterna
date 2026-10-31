export * from './types';
export { analyze, ENGINE_VERSION, CATEGORY_LABELS, corporateDomain, primaryAdapter } from './analyze';
export type { CorporateDomain } from './analyze';
export { METRICS, METRIC_LIST } from './kb/metrics';
export { ACTIONS } from './kb/actions';
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
export { documentParts, renderDocument } from './document';
export type { DocOptions } from './document';
export { BUGCHECKS, dateIt, WIN10_EOS, WIN10_ESU_CONSUMER, WIN11_EOS } from './pc';
export { attrState, bytesText, diskStatus, isFlashDisk, smartId, smartName, smartRaw, STATUS_LABEL } from './smart';
export type { AttrState, DiskSignal, DiskStatus } from './smart';
export { cacheText, channelMode, channelOf, coreLayout, cpuVendor, memVendor, moduleText } from './hardware';
export type { ChannelMode } from './hardware';
export { pctText, reclaimableBytes, sizeText, spaceHintLabel, spaceLine, SPACE_CATEGORY_LABEL, SPACE_HINTS, SPACE_RISK_LABEL, unattributedBytes } from './space';
export type { SpaceHintInfo, SpaceRisk } from './space';
export { THREAT_SEVERITY, THREAT_STATUS, unresolved as unresolvedThreat } from './defender';
