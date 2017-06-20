<?php if ( !defined( 'WI_VERSION' ) ) die( -1 ); ?>

<div class="toolbar">
<?php $toolBar->render() ?>
</div>

<div style="float: right">
<?php
echo $this->imageAndTextLink( '/client/securityplugin.php?install=yes', '/common/images/edit-modify-16.png', $this->tr( 'Install Plugin' ) );
echo ' | ' . $this->imageAndTextLink( '/client/securityplugin.php?install=no' , '/common/images/edit-delete-16.png', $this->tr( 'Uninstall Plugin' ) );
?>
</div>


<?php if ( $install_security == "do" ): ?>
<div class="comment-text">Installation finished</div>
<?php elseif ( $install_security == "no" ): ?>
<div class="comment-text">Uninstallation finished</div>
<?php elseif ( $install_security == "yes" ): ?>
<div class="comment-text">Installation</div>

<?php $form->renderFormOpen(); ?>
<?php $form->renderText( $this->tr( 'openvas_ws_login:' ), 'openvas_ws_login', array( 'size' => 80 ) ); ?>
<?php $form->renderText( $this->tr( 'openvas_ws_password:' ), 'openvas_ws_password', array( 'size' => 80 ) ); ?>
<?php $form->renderText( $this->tr( 'openvas_ws_endpoint:' ), 'openvas_ws_endpoint', array( 'size' => 80 ) ); ?>
<?php $form->renderText( $this->tr( 'type_folder_bugs:' ), 'type_folder_bugs', array( 'size' => 80 ) ); ?>
<div class="form-submit">
<?php $form->renderSubmit( $this->tr( 'OK' ), 'ok' ); ?>
<?php $form->renderSubmit( $this->tr( 'Cancel' ), 'cancel' ); ?>
</div>
<?php $form->renderFormClose() ?>

<?php elseif( empty($install_security) && !empty($alertscanid) ): ?>
<div class="comment-text">Scan openvas finished</div>
<?php else: ?>
<div class="comment-text">Choose an option</div>
<?php endif ?>
