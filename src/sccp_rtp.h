/*!
 * \file        sccp_rtp.h
 * \brief       SCCP RTP Header
 * \author      Marcello Ceschia <marcelloceschia [at] users.sourceforge.net>
 * \note        This program is free software and may be modified and distributed under the terms of the GNU Public License.
 *              See the LICENSE file at the top of the source tree.
 *
 * $Date$
 * $Revision$  
 */
#pragma once

struct sccp_rtp_new;

struct sccp_rtp_new;

/*!
 * \brief SCCP RTP Structure
 */
struct sccp_rtp {
//	sccp_mutex_t lock;
	PBX_RTP_TYPE *rtp;											/*!< pbx rtp pointer */
//	uint16_t readState;											/*!< current read state */
//	uint16_t writeState;											/*!< current write state */
//	boolean_t directMedia;											/*!< Show if we are running in directmedia mode (set in pbx_impl during rtp bridging) */
//	skinny_codec_t readFormat;										/*!< current read format */
//	skinny_codec_t writeFormat;										/*!< current write format */
//	struct sockaddr_storage phone;										/*!< our phone information (openreceive) */
//	struct sockaddr_storage phone_remote;									/*!< phone destination address (starttransmission) */
};														/*!< SCCP RTP Structure */

sccp_rtp_new_t __attribute__ ((malloc)) *const sccp_rtp_ctor(constChannelPtr channel, sccp_rtp_type_t type);
boolean_t sccp_rtp_createServer(sccp_rtp_new_t *const rtp);
boolean_t sccp_rtp_stop(sccp_rtp_new_t *const rtp);
boolean_t sccp_rtp_destroyServer(sccp_rtp_new_t *const rtp);
sccp_rtp_new_t *const sccp_rtp_dtor(sccp_rtp_new_t *rtp);

boolean_t sccp_rtp_getPeer(const sccp_rtp_new_t *const rtp, struct sockaddr_storage *const sas);	/* get peer phone (other channel side) */
boolean_t sccp_rtp_setPeer(sccp_rtp_new_t *const rtp, const struct sockaddr_storage *const sas);	/* set peer phone (other channel side) and update pbx*/

boolean_t sccp_rtp_getPhone(const sccp_rtp_new_t * const rtp, struct sockaddr_storage *const sas);	/* get phone address*/
boolean_t sccp_rtp_setPhone(sccp_rtp_new_t * const rtp, const struct sockaddr_storage *const sas);	/* set phone address and update pbx */

boolean_t sccp_rtp_updateRemoteNat(sccp_rtp_new_t *const rtp);						/* update nat addressing, if required */
PBX_RTP_TYPE * sccp_rtp_getPbxRtp(const sccp_rtp_new_t * const rtp);					/* get pointer to pbx's rtp structure */

uint16_t sccp_rtp_getReadState(const sccp_rtp_new_t * const rtp);
boolean_t sccp_rtp_setReadState(sccp_rtp_new_t * const rtp, uint16_t value);
boolean_t sccp_rtp_toggleReadState(sccp_rtp_new_t * const rtp, uint16_t value);

uint16_t sccp_rtp_getWriteState(const sccp_rtp_new_t * const rtp);
boolean_t sccp_rtp_setWriteState(sccp_rtp_new_t * const rtp, uint16_t value);
boolean_t sccp_rtp_toggleWriteState(sccp_rtp_new_t * const rtp, uint16_t value);

skinny_codec_t sccp_rtp_getReadFormat(const sccp_rtp_new_t * const rtp);
skinny_codec_t sccp_rtp_getWriteFormat(const sccp_rtp_new_t * const rtp);
boolean_t sccp_rtp_setReadFormat(sccp_rtp_new_t * const rtp, skinny_codec_t codec);
boolean_t sccp_rtp_setWriteFormat(sccp_rtp_new_t * const rtp, skinny_codec_t codec);
boolean_t sccp_rtp_sendReadFormatToPbx(const sccp_rtp_new_t * const rtp);
boolean_t sccp_rtp_sendWriteFormatToPbx(const sccp_rtp_new_t * const rtp);

boolean_t sccp_rtp_isDirectMedia(const sccp_rtp_new_t * const rtp);
boolean_t sccp_rtp_setDirectMedia(sccp_rtp_new_t * const rtp, boolean_t direct);

int sccp_rtp_getPhoneAddress(const sccp_rtp_new_t * const rtp, struct sockaddr_storage *const sas);
int sccp_rtp_getRemotePhoneAddress(const sccp_rtp_new_t * const rtp, struct sockaddr_storage *const sas);
/*
boolean_t sccp_rtp_setPhoneAddress(sccp_rtp_new_t * const rtp, const struct sockaddr_storage *const sas);
boolean_t sccp_rtp_setRemotePhoneAddress(sccp_rtp_new_t * const rtp, const struct sockaddr_storage *const sas);
*/
// kate: indent-width 8; replace-tabs off; indent-mode cstyle; auto-insert-doxygen on; line-numbers on; tab-indents on; keep-extra-spaces off; auto-brackets off;
