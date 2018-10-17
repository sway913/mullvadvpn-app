// @flow

import { Styles } from 'reactxp';
import { colors } from '../../config';

export default {
  advanced_settings: Styles.createViewStyle({
    backgroundColor: colors.darkBlue,
    flex: 1,
  }),
  advanced_settings__container: Styles.createViewStyle({
    flexDirection: 'column',
    flex: 1,
  }),
  advanced_settings__scrollview: Styles.createViewStyle({
    flexGrow: 1,
    flexShrink: 1,
    flexBasis: '100%',
  }),
  advanced_settings__content: Styles.createViewStyle({
    flexDirection: 'column',
    flexGrow: 1,
    flexShrink: 0,
    flexBasis: 'auto',
    overflow: 'visible',
  }),
  advanced_settings__cell: Styles.createViewStyle({
    cursor: 'default',
    backgroundColor: colors.green,
    flexDirection: 'row',
    paddingTop: 14,
    paddingBottom: 14,
    paddingLeft: 24,
    paddingRight: 24,
    marginBottom: 1,
    justifyContent: 'flex-start',
  }),
  advanced_settings__cell_hover: Styles.createViewStyle({
    backgroundColor: colors.blue80,
  }),
  advanced_settings__cell_selected_hover: Styles.createViewStyle({
    backgroundColor: colors.green,
  }),
  advanced_settings__cell_spacer: Styles.createViewStyle({
    height: 24,
  }),
  advanced_settings__cell_icon: Styles.createViewStyle({
    width: 24,
    height: 24,
    marginRight: 8,
    flex: 0,
    color: colors.white80,
  }),
  advanced_settings__cell_dimmed: Styles.createViewStyle({
    cursor: 'default',
    paddingTop: 14,
    paddingBottom: 14,
    paddingLeft: 24,
    paddingRight: 24,
    marginBottom: 1,
    backgroundColor: colors.blue40,
    flexDirection: 'row',
    justifyContent: 'flex-start',
  }),

  advanced_settings__section_title: Styles.createTextStyle({
    backgroundColor: colors.blue,
    paddingTop: 14,
    paddingBottom: 14,
    paddingLeft: 24,
    paddingRight: 24,
    marginBottom: 1,
    fontFamily: 'DINPro',
    fontSize: 20,
    fontWeight: '900',
    lineHeight: 26,
    color: colors.white,
  }),
  advanced_settings__cell_label: Styles.createTextStyle({
    fontFamily: 'DINPro',
    fontSize: 20,
    fontWeight: '900',
    lineHeight: 26,
    letterSpacing: -0.2,
    color: colors.white,
    flex: 0,
  }),
  advanced_settings__mssfix_frame: Styles.createViewStyle({
    flexGrow: 0,
    flexShrink: 0,
    flexBasis: 80,
  }),
  advanced_settings__mssfix_valid_value: Styles.createTextStyle({
    color: colors.white,
  }),
  advanced_settings__mssfix_invalid_value: Styles.createTextStyle({
    color: colors.red,
  }),
};
